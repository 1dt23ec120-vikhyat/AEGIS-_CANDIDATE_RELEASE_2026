"""Attack Analysis Engine (M11 Phase C).

Deterministic, explainable attack analysis composed over the existing graph query
and analytics services. It reconstructs attack chains and timelines, maps nodes to
kill-chain phases, discovers compromise paths and infrastructure clusters, infers
incident root causes, and reports threat propagation — all by reusing existing
traversal primitives. No new graph algorithm, no persistence.
"""

from __future__ import annotations

from datetime import datetime

from core.domain.analytics_view import PropagationAnalysis
from core.domain.attack_view import (
    AttackChain,
    AttackChainStep,
    AttackTimeline,
    CompromisePath,
    InfrastructureCluster,
    KillChainMapping,
    RootCause,
    TimelineEntry,
)
from core.domain.graph import GraphNode, NodeType
from core.interfaces.logger import ILogger
from services.analytics.graph_analytics import GraphAnalyticsService
from services.analytics.observability import MeteredService, tracked
from services.graph.query import GraphQueryService

_DEFAULT_DEPTH = 4
_DEFAULT_TOP = 10
_ARTIFACT_TYPES = frozenset({NodeType.FILE, NodeType.URL, NodeType.EMAIL, NodeType.ARTIFACT})
_INFRA_TYPES = frozenset({NodeType.IOC, NodeType.DOMAIN, NodeType.IP_ADDRESS, NodeType.HASH})
_MIN_CLUSTER_SIZE = 2
_MIN_SPAN_POINTS = 2

# Deterministic node-type -> Lockheed-Martin kill-chain phase mapping.
_KILL_CHAIN_PHASE: dict[NodeType, str] = {
    NodeType.PROVIDER: "reconnaissance",
    NodeType.FILE: "weaponization",
    NodeType.HASH: "weaponization",
    NodeType.URL: "delivery",
    NodeType.EMAIL: "delivery",
    NodeType.ARTIFACT: "delivery",
    NodeType.THREAT: "exploitation",
    NodeType.DOMAIN: "command_and_control",
    NodeType.IP_ADDRESS: "command_and_control",
    NodeType.IOC: "command_and_control",
    NodeType.INCIDENT: "actions_on_objectives",
    NodeType.CAMPAIGN: "actions_on_objectives",
    NodeType.INVESTIGATION: "actions_on_objectives",
}
_PHASE_ORDER = (
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
)


class AttackAnalysisService(MeteredService):
    """Deterministic attack analysis over the knowledge graph."""

    def __init__(
        self,
        query: GraphQueryService,
        analytics: GraphAnalyticsService,
        logger: ILogger,
    ) -> None:
        """Initialize the attack analysis service.

        Args:
            query: The graph query service (traversal primitives).
            analytics: The Phase A analytics engine (reused for propagation).
            logger: Injected logger.
        """
        super().__init__()
        self._query = query
        self._analytics = analytics
        self._logger = logger

    @tracked
    def attack_chain(self, origin_id: str, target_id: str) -> AttackChain:
        """Reconstruct an ordered attack chain between two nodes."""
        path = self._query.shortest_path(origin_id, target_id)
        steps = tuple(
            AttackChainStep(
                order=index,
                node_id=node.node_id,
                node_type=node.node_type.value,
                label=node.display_name,
                kill_chain_phase=_phase(node),
                timestamp=self._node_timestamp(node.node_id),
            )
            for index, node in enumerate(path.nodes)
        )
        rationale = (
            (f"Shortest path of {len(steps)} node(s) from {origin_id} to {target_id}",)
            if steps
            else (f"No path found from {origin_id} to {target_id}",)
        )
        return AttackChain(
            origin_id=origin_id, target_id=target_id, steps=steps, rationale=rationale
        )

    @tracked
    def kill_chain_mapping(
        self, root_id: str, *, max_depth: int = _DEFAULT_DEPTH
    ) -> KillChainMapping:
        """Map the nodes reachable from a root to kill-chain phases."""
        reachable = self._reachable_including_self(root_id, max_depth)
        buckets: dict[str, list[str]] = {phase: [] for phase in _PHASE_ORDER}
        for node in reachable:
            buckets[_phase(node)].append(node.node_id)
        phases = tuple(
            (phase, tuple(sorted(buckets[phase]))) for phase in _PHASE_ORDER if buckets[phase]
        )
        rationale = (f"{len(reachable)} node(s) mapped across {len(phases)} kill-chain phase(s)",)
        return KillChainMapping(phases=phases, rationale=rationale)

    @tracked
    def compromise_paths(self, source_id: str, target_id: str) -> tuple[CompromisePath, ...]:
        """Discover compromise path(s) between two nodes (shortest first)."""
        paths = []
        for path in self._analytics.shortest_attack_paths(source_id, target_id):
            paths.append(
                CompromisePath(
                    source_id=source_id,
                    target_id=target_id,
                    node_ids=path.node_ids,
                    hops=path.hops,
                    rationale=(f"{path.hops}-hop compromise path",),
                )
            )
        return tuple(paths)

    @tracked
    def root_cause(self, incident_id: str, *, max_depth: int = _DEFAULT_DEPTH) -> RootCause:
        """Infer the root cause (earliest origin artifact) of an incident."""
        reachable = self._query.reachable(incident_id, max_depth=max_depth)
        artifacts = [n for n in reachable if n.node_type in _ARTIFACT_TYPES]
        if not artifacts:
            return RootCause(
                incident_id=incident_id,
                rationale=("No artifact found in the incident subgraph",),
            )
        # Deterministic: earliest first-seen, then node id.
        ranked = sorted(
            artifacts, key=lambda n: (self._node_timestamp(n.node_id) or "~", n.node_id)
        )
        root = ranked[0]
        return RootCause(
            incident_id=incident_id,
            root_id=root.node_id,
            root_type=root.node_type.value,
            root_label=root.display_name,
            first_seen=self._node_timestamp(root.node_id),
            evidence_ids=tuple(sorted(n.node_id for n in artifacts)),
            rationale=(
                f"Earliest artifact ({root.node_type.value}) in the incident subgraph",
                f"{len(artifacts)} artifact(s) considered",
            ),
        )

    @tracked
    def threat_propagation(
        self, node_id: str, *, max_depth: int = _DEFAULT_DEPTH
    ) -> PropagationAnalysis:
        """Threat propagation from a node (reuses the analytics engine)."""
        return self._analytics.threat_propagation(node_id, max_depth=max_depth)

    @tracked
    def infrastructure_clusters(
        self, *, top: int = _DEFAULT_TOP
    ) -> tuple[InfrastructureCluster, ...]:
        """Clusters of artifacts sharing a common infrastructure node."""
        clusters: list[InfrastructureCluster] = []
        for infra in self._all_nodes():
            if infra.node_type not in _INFRA_TYPES:
                continue
            members = tuple(
                sorted(
                    n.node_id
                    for n in self._query.neighbors(infra.node_id)
                    if n.node_type in _ARTIFACT_TYPES
                )
            )
            if len(members) < _MIN_CLUSTER_SIZE:  # a cluster needs &ge;2 artifacts
                continue
            clusters.append(
                InfrastructureCluster(
                    infra_id=infra.node_id,
                    infra_type=infra.node_type.value,
                    infra_label=infra.display_name,
                    member_ids=members,
                    rationale=(
                        f"{len(members)} artifacts share {infra.node_type.value} {infra.node_id}",
                    ),
                )
            )
        clusters.sort(key=lambda c: (-c.size, c.infra_id))
        return tuple(clusters[:top])

    @tracked
    def attack_timeline(self, root_id: str, *, max_depth: int = _DEFAULT_DEPTH) -> AttackTimeline:
        """Reconstruct the time-ordered relationships in an attack subgraph."""
        reachable_ids = {n.node_id for n in self._reachable_including_self(root_id, max_depth)}
        seen: set[str] = set()
        entries: list[TimelineEntry] = []
        for nid in reachable_ids:
            for edge in self._query.edges_of(nid):
                if edge.edge_id in seen:
                    continue
                if edge.source_id in reachable_ids and edge.target_id in reachable_ids:
                    seen.add(edge.edge_id)
                    entries.append(
                        TimelineEntry(
                            timestamp=edge.timestamp,
                            source_id=edge.source_id,
                            target_id=edge.target_id,
                            relationship=edge.relationship.value,
                            description=(
                                f"{edge.source_id} {edge.relationship.value} {edge.target_id}"
                            ),
                        )
                    )
        entries.sort(key=lambda e: (e.timestamp, e.source_id, e.target_id))
        return AttackTimeline(
            root_id=root_id,
            entries=tuple(entries),
            span_days=_span_days(entries),
            rationale=(f"{len(entries)} relationship(s) ordered by observation time",),
        )

    # --- internals -------------------------------------------------------

    def _all_nodes(self) -> tuple[GraphNode, ...]:
        return self._query.all_nodes()

    def _reachable_including_self(self, node_id: str, max_depth: int) -> tuple[GraphNode, ...]:
        reachable = self._query.reachable(node_id, max_depth=max_depth)
        if any(n.node_id == node_id for n in reachable):
            return reachable
        node = self._query.lookup(node_id)
        return (node, *reachable) if node else reachable

    def _node_timestamp(self, node_id: str) -> str:
        stamps = sorted(e.timestamp for e in self._query.edges_of(node_id) if e.timestamp)
        return stamps[0] if stamps else ""


def _phase(node: GraphNode) -> str:
    return _KILL_CHAIN_PHASE.get(node.node_type, "delivery")


def _span_days(entries: list[TimelineEntry]) -> float:
    stamps = sorted(e.timestamp for e in entries if e.timestamp)
    if len(stamps) < _MIN_SPAN_POINTS:
        return 0.0
    try:
        delta = datetime.fromisoformat(stamps[-1]) - datetime.fromisoformat(stamps[0])
        return round(delta.total_seconds() / 86400.0, 3)
    except ValueError:
        return 0.0

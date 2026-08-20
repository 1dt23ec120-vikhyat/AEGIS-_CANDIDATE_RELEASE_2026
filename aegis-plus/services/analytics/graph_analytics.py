"""Graph Analytics Engine (M11 Phase A).

A reusable, deterministic analytics service built entirely on top of the existing
:class:`services.graph.query.GraphQueryService`. It composes the graph's traversal
primitives (degree, centrality, components, density, reachability, shortest paths)
into structured, display-ready analytics DTOs. It reimplements no graph algorithm
— every method delegates to the query service — and holds no state beyond
observability counters.
"""

from __future__ import annotations

from core.domain.analytics_view import (
    AttackPathView,
    BlastRadiusEstimate,
    ComponentAnalysis,
    GraphAnalyticsReport,
    NeighborhoodAnalysis,
    PropagationAnalysis,
    RankedNode,
    ReachabilitySummary,
    SharedInfrastructure,
)
from core.domain.graph import GraphNode, NodeType
from core.interfaces.logger import ILogger
from services.analytics.observability import MeteredService, tracked
from services.graph.query import GraphQueryService

_DEFAULT_TOP = 10
_DEFAULT_DEPTH = 3

_INFRA_TYPES = frozenset({NodeType.IOC, NodeType.DOMAIN, NodeType.IP_ADDRESS, NodeType.HASH})
_ARTIFACT_TYPES = frozenset({NodeType.FILE, NodeType.URL, NodeType.EMAIL, NodeType.ARTIFACT})


class GraphAnalyticsService(MeteredService):
    """Deterministic graph analytics composed over the graph query service."""

    def __init__(self, query: GraphQueryService, logger: ILogger) -> None:
        """Initialize the analytics service.

        Args:
            query: The graph query service providing all traversal primitives.
            logger: Injected logger.
        """
        super().__init__()
        self._query = query
        self._logger = logger

    # --- node-level analytics -------------------------------------------

    @tracked
    def node_degree(self, node_id: str) -> int:
        """The number of relationships incident to a node."""
        return len(self._query.edges_of(node_id))

    @tracked
    def degree_ranking(self, *, top: int = _DEFAULT_TOP) -> tuple[RankedNode, ...]:
        """Nodes ranked by degree (highest first), deterministically."""
        ranked = [
            self._ranked(node, float(len(self._query.edges_of(node.node_id))))
            for node in self._query.all_nodes()
        ]
        return self._top(ranked, top)

    @tracked
    def centrality_ranking(self, *, top: int = _DEFAULT_TOP) -> tuple[RankedNode, ...]:
        """Nodes ranked by degree centrality (highest first)."""
        ranked = [
            self._ranked(node, self._query.centrality(node.node_id))
            for node in self._query.all_nodes()
        ]
        return self._top(ranked, top)

    # --- structural analytics -------------------------------------------

    @tracked
    def component_analysis(self) -> ComponentAnalysis:
        """Connected-component structure of the graph."""
        components = self._query.connected_components()
        sizes = tuple(sorted((len(c) for c in components), reverse=True))
        return ComponentAnalysis(
            component_count=len(components),
            largest_size=sizes[0] if sizes else 0,
            sizes=sizes,
            isolated_count=sum(1 for size in sizes if size == 1),
        )

    @tracked
    def relationship_density(self) -> float:
        """Undirected graph density in ``[0, 1]``."""
        return self._query.graph_density()

    # --- reachability / propagation -------------------------------------

    @tracked
    def blast_radius(self, node_id: str, *, max_depth: int = _DEFAULT_DEPTH) -> BlastRadiusEstimate:
        """Estimate the blast radius (reachable set) of a node."""
        reachable = self._query.reachable(node_id, max_depth=max_depth)
        ids = tuple(sorted(n.node_id for n in reachable))
        return BlastRadiusEstimate(
            origin_id=node_id,
            reachable_count=len(ids),
            reachable_ids=ids,
            max_depth=max_depth,
        )

    @tracked
    def reachability(self, node_id: str, *, max_depth: int = _DEFAULT_DEPTH) -> ReachabilitySummary:
        """Summarise what is reachable from a node within a depth bound."""
        reachable = self._query.reachable(node_id, max_depth=max_depth)
        return ReachabilitySummary(
            origin_id=node_id,
            reachable_count=len(reachable),
            max_depth=max_depth,
            by_type=self._type_counts(reachable),
        )

    @tracked
    def threat_propagation(
        self, node_id: str, *, max_depth: int = _DEFAULT_DEPTH
    ) -> PropagationAnalysis:
        """Analyse how a threat propagates from an origin across the graph."""
        reachable = self._query.reachable(node_id, max_depth=max_depth)
        impacted_ids = tuple(sorted(n.node_id for n in reachable))
        threat_count = sum(1 for n in reachable if n.node_type is NodeType.THREAT)
        return PropagationAnalysis(
            origin_id=node_id,
            impacted_count=len(impacted_ids),
            impacted_ids=impacted_ids,
            threat_count=threat_count,
            max_depth=max_depth,
        )

    # --- paths / neighbourhoods -----------------------------------------

    @tracked
    def shortest_attack_paths(self, source_id: str, target_id: str) -> tuple[AttackPathView, ...]:
        """Candidate shortest attack path(s) between two nodes."""
        views = []
        for path in self._query.attack_paths(source_id, target_id):
            node_ids = tuple(n.node_id for n in path.nodes)
            views.append(
                AttackPathView(
                    source_id=source_id,
                    target_id=target_id,
                    hops=max(len(node_ids) - 1, 0),
                    node_ids=node_ids,
                )
            )
        return tuple(views)

    @tracked
    def neighborhood(self, node_id: str, *, hops: int = 1) -> NeighborhoodAnalysis:
        """Multi-hop neighbourhood analysis around a node."""
        reachable = self._query.reachable(node_id, max_depth=hops)
        ids = {n.node_id for n in reachable} | {node_id}
        edge_count = sum(
            1
            for nid in ids
            for edge in self._query.edges_of(nid)
            if edge.source_id in ids and edge.target_id in ids
        )
        # Each undirected edge is counted from both endpoints above.
        return NeighborhoodAnalysis(
            origin_id=node_id,
            hops=hops,
            node_count=len(ids),
            edge_count=edge_count // 2,
            by_type=self._type_counts(reachable),
        )

    # --- shared infrastructure ------------------------------------------

    @tracked
    def shared_infrastructure(
        self, node_id: str, *, top: int = _DEFAULT_TOP
    ) -> tuple[SharedInfrastructure, ...]:
        """Peers that share infrastructure/IOCs with the given node.

        Traverses origin → infrastructure node (IOC/domain/IP/hash) → peer
        artifact, reusing the query service's neighbour traversal, then confirms
        the shared set via ``shared_iocs``.
        """
        peers: dict[str, GraphNode] = {}
        for infra in self._query.neighbors(node_id):
            if infra.node_type not in _INFRA_TYPES:
                continue
            for peer in self._query.neighbors(infra.node_id):
                if peer.node_id == node_id or peer.node_type not in _ARTIFACT_TYPES:
                    continue
                peers[peer.node_id] = peer
        results: list[SharedInfrastructure] = []
        for peer in peers.values():
            shared = self._query.shared_iocs(node_id, peer.node_id)
            if not shared:
                continue
            results.append(
                SharedInfrastructure(
                    origin_id=node_id,
                    peer_id=peer.node_id,
                    peer_type=peer.node_type.value,
                    peer_label=peer.display_name,
                    shared_ids=tuple(sorted(n.node_id for n in shared)),
                )
            )
        results.sort(key=lambda s: (-s.shared_count, s.peer_id))
        return tuple(results[:top])

    # --- aggregate -------------------------------------------------------

    @tracked
    def report(self, *, top: int = 5) -> GraphAnalyticsReport:
        """Aggregate analytics snapshot for dashboards."""
        snap = self._query.snapshot()
        return GraphAnalyticsReport(
            node_count=snap.node_count,
            edge_count=snap.edge_count,
            density=self._query.graph_density(),
            components=self.component_analysis(),
            top_degree=self.degree_ranking(top=top),
            top_central=self.centrality_ranking(top=top),
        )

    # --- helpers ---------------------------------------------------------

    def _ranked(self, node: GraphNode, score: float) -> RankedNode:
        return RankedNode(
            node_id=node.node_id,
            node_type=node.node_type.value,
            label=node.display_name,
            score=round(score, 6),
            degree=len(self._query.edges_of(node.node_id)),
            risk_percent=_risk_percent(node),
        )

    @staticmethod
    def _top(ranked: list[RankedNode], top: int) -> tuple[RankedNode, ...]:
        ranked.sort(key=lambda r: (-r.score, r.node_id))
        return tuple(ranked[:top])

    @staticmethod
    def _type_counts(nodes: tuple[GraphNode, ...]) -> tuple[tuple[str, int], ...]:
        counts: dict[str, int] = {}
        for node in nodes:
            key = node.node_type.value
            counts[key] = counts.get(key, 0) + 1
        return tuple(sorted(counts.items()))


def _risk_percent(node: GraphNode) -> int:
    """Best-effort risk percentage from node metadata (0 when absent)."""
    raw = node.metadata.get("risk_score", "")
    try:
        return max(0, min(100, round(float(raw) * 100)))
    except (TypeError, ValueError):
        return 0

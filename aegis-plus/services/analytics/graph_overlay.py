"""Graph Overlay Service (M11 Phase E).

Produces per-node overlay annotations for the Intelligence Graph Explorer:
risk colouring, critical-node highlighting, campaign/cluster membership, attack-path
membership, and propagation rank. It extends the Explorer without redesigning it —
the presentation layer applies these annotations to the existing canvas. All data
is composed from the Phase A/C services; nothing new is computed here.
"""

from __future__ import annotations

from core.domain.graph import NodeType
from core.domain.soc_analytics_view import GraphOverlay, NodeOverlay
from core.interfaces.logger import ILogger
from services.analytics.attack_analysis import AttackAnalysisService
from services.analytics.graph_analytics import GraphAnalyticsService
from services.analytics.observability import MeteredService, tracked
from services.graph.query import GraphQueryService

_DEFAULT_TOP = 10
_CAMPAIGN_DEPTH = 2
_MIN_PATH_MEMBERS = 2
_ARTIFACT_TYPES = frozenset({NodeType.FILE, NodeType.URL, NodeType.EMAIL, NodeType.ARTIFACT})


class GraphOverlayService(MeteredService):
    """Deterministic Explorer overlay annotations composed from the engine."""

    def __init__(
        self,
        query: GraphQueryService,
        analytics: GraphAnalyticsService,
        attack: AttackAnalysisService,
        logger: ILogger,
    ) -> None:
        """Initialize the graph overlay service.

        Args:
            query: The graph query service.
            analytics: The Phase A analytics engine (centrality).
            attack: The Phase C attack analysis engine (clusters, paths).
            logger: Injected logger.
        """
        super().__init__()
        self._query = query
        self._analytics = analytics
        self._attack = attack
        self._logger = logger

    @tracked
    def overlay(self, *, top: int = _DEFAULT_TOP) -> GraphOverlay:
        """Compute overlay annotations for every node in the graph."""
        central = self._analytics.centrality_ranking(top=top)
        central_rank = {r.node_id: rank for rank, r in enumerate(central, start=1)}
        critical_ids = tuple(sorted(central_rank))

        clusters = self._attack.infrastructure_clusters(top=top)
        cluster_map: dict[str, str] = {}
        for cluster in clusters:
            for member in cluster.member_ids:
                cluster_map.setdefault(member, cluster.infra_id)

        campaign_map = self._campaign_map()

        path_ids: set[str] = set()
        for cluster in clusters:
            members = cluster.member_ids
            if len(members) >= _MIN_PATH_MEMBERS:
                for path in self._attack.compromise_paths(members[0], members[1]):
                    path_ids.update(path.node_ids)

        overlays = tuple(
            NodeOverlay(
                node_id=node.node_id,
                risk_percent=_risk_percent(node.metadata.get("risk_score", "")),
                is_critical=node.node_id in central_rank,
                campaign_id=campaign_map.get(node.node_id, ""),
                cluster_id=cluster_map.get(node.node_id, ""),
                on_attack_path=node.node_id in path_ids,
                propagation_rank=central_rank.get(node.node_id, 0),
            )
            for node in sorted(self._query.all_nodes(), key=lambda n: n.node_id)
        )
        return GraphOverlay(
            nodes=overlays,
            attack_path_ids=tuple(sorted(path_ids)),
            critical_ids=critical_ids,
            top_central=central,
        )

    # --- internals -------------------------------------------------------

    def _campaign_map(self) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for node in self._query.all_nodes():
            if node.node_type is not NodeType.CAMPAIGN:
                continue
            for member in self._query.reachable(node.node_id, max_depth=_CAMPAIGN_DEPTH):
                if member.node_type in _ARTIFACT_TYPES:
                    mapping.setdefault(member.node_id, node.node_id)
        return mapping


def _risk_percent(raw: str) -> int:
    try:
        return max(0, min(100, round(float(raw) * 100)))
    except (TypeError, ValueError):
        return 0

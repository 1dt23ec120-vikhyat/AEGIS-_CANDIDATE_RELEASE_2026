"""SOC analytics and graph-overlay contracts (view DTOs) for M11 Phase E.

Aggregate, display-ready value objects that extend — never replace — the existing
SOC dashboard and Graph Explorer. They compose the Phase A-D result DTOs into
dashboard widgets and per-node overlay annotations for the Explorer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.domain.analytics_view import RankedNode
from core.domain.attack_view import CompromisePath, InfrastructureCluster
from core.domain.intelligence_view import CampaignIntelligence, IOCIntelligence, ThreatScore
from core.domain.recommendation_view import Recommendation


@dataclass(frozen=True, slots=True)
class AnalyticsOverview:
    """Aggregate analytics for the SOC dashboard's advanced widgets."""

    threat_priorities: tuple[ThreatScore, ...] = ()
    emerging_campaigns: tuple[CampaignIntelligence, ...] = ()
    ioc_trends: tuple[IOCIntelligence, ...] = ()
    infrastructure_reuse: tuple[InfrastructureCluster, ...] = ()
    critical_attack_paths: tuple[CompromisePath, ...] = ()
    threat_distribution: tuple[tuple[str, int], ...] = ()
    recommendations: tuple[Recommendation, ...] = ()


@dataclass(frozen=True, slots=True)
class NodeOverlay:
    """Overlay annotations for a single graph node (Explorer colouring)."""

    node_id: str
    risk_percent: int = 0
    is_critical: bool = False
    campaign_id: str = ""
    cluster_id: str = ""
    on_attack_path: bool = False
    propagation_rank: int = 0


@dataclass(frozen=True, slots=True)
class GraphOverlay:
    """A set of overlay annotations plus highlighted attack paths."""

    nodes: tuple[NodeOverlay, ...] = ()
    attack_path_ids: tuple[str, ...] = ()
    critical_ids: tuple[str, ...] = ()
    top_central: tuple[RankedNode, ...] = field(default_factory=tuple)

    def for_node(self, node_id: str) -> NodeOverlay | None:
        """Return the overlay for a node, if present."""
        for overlay in self.nodes:
            if overlay.node_id == node_id:
                return overlay
        return None

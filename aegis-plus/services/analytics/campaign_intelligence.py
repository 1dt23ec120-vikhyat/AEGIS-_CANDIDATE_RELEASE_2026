"""Campaign Intelligence Service (M11 Phase B).

Deterministic intelligence about campaign nodes: size, IOC/infrastructure reuse,
evolution over time, and pairwise similarity (shared IOCs / infrastructure). Built
on the existing graph query service; reuses ``reachable`` and ``shared_iocs`` and
introduces no new graph algorithm.
"""

from __future__ import annotations

from datetime import datetime

from core.domain.graph import GraphNode, NodeType
from core.domain.intelligence_view import CampaignIntelligence, CampaignSimilarity
from core.interfaces.logger import ILogger
from services.analytics.observability import MeteredService, tracked
from services.graph.query import GraphQueryService

_DEFAULT_TOP = 10
_CAMPAIGN_DEPTH = 2
_INFRA_TYPES = frozenset({NodeType.IOC, NodeType.DOMAIN, NodeType.IP_ADDRESS, NodeType.HASH})
_ARTIFACT_TYPES = frozenset({NodeType.FILE, NodeType.URL, NodeType.EMAIL, NodeType.ARTIFACT})


class CampaignIntelligenceService(MeteredService):
    """Deterministic campaign intelligence over the knowledge graph."""

    def __init__(self, query: GraphQueryService, logger: ILogger) -> None:
        """Initialize the campaign intelligence service.

        Args:
            query: The graph query service (source of campaign subgraphs).
            logger: Injected logger.
        """
        super().__init__()
        self._query = query
        self._logger = logger

    @tracked
    def analyze(self, campaign_id: str) -> CampaignIntelligence:
        """Compute intelligence for a single campaign node."""
        return self._compute(campaign_id)

    @tracked
    def rank(self, *, top: int = _DEFAULT_TOP) -> tuple[CampaignIntelligence, ...]:
        """Rank campaigns by artifact count then IOC count (deterministic)."""
        intel = [self._compute(n.node_id) for n in self._campaigns()]
        intel.sort(key=lambda c: (-c.artifact_count, -c.ioc_count, c.campaign_id))
        return tuple(intel[:top])

    @tracked
    def similarity(self, campaign_a: str, campaign_b: str) -> CampaignSimilarity:
        """Similarity of two campaigns by shared IOCs/infrastructure (Jaccard)."""
        infra_a = self._infrastructure_ids(campaign_a)
        infra_b = self._infrastructure_ids(campaign_b)
        shared = infra_a & infra_b
        union = infra_a | infra_b
        ioc_shared = {
            nid
            for nid in shared
            if (node := self._query.lookup(nid)) and node.node_type is NodeType.IOC
        }
        jaccard = len(shared) / len(union) if union else 0.0
        rationale = (
            f"{len(shared)} shared infrastructure node(s)",
            f"{len(ioc_shared)} shared IOC(s)",
            f"Jaccard similarity {jaccard:.2f}",
        )
        return CampaignSimilarity(
            campaign_a=campaign_a,
            campaign_b=campaign_b,
            shared_iocs=len(ioc_shared),
            shared_infrastructure=len(shared),
            similarity=round(jaccard, 4),
            rationale=rationale,
        )

    # --- internals -------------------------------------------------------

    def _compute(self, campaign_id: str) -> CampaignIntelligence:
        node = self._query.lookup(campaign_id)
        label = node.display_name if node else campaign_id
        reachable = self._query.reachable(campaign_id, max_depth=_CAMPAIGN_DEPTH)
        artifacts = [n for n in reachable if n.node_type in _ARTIFACT_TYPES]
        iocs = [n for n in reachable if n.node_type is NodeType.IOC]
        infra = [n for n in reachable if n.node_type in _INFRA_TYPES]
        first_seen, last_seen, evolution = self._evolution(campaign_id)
        shared_ioc_score = len(iocs) / len(artifacts) if artifacts else 0.0
        rationale = (
            f"{len(artifacts)} artifact(s) in campaign",
            f"{len(iocs)} IOC(s), {len(infra)} infrastructure node(s)",
            f"Evolution span {evolution:.1f} day(s)",
        )
        return CampaignIntelligence(
            campaign_id=campaign_id,
            label=label,
            artifact_count=len(artifacts),
            ioc_count=len(iocs),
            infrastructure_count=len(infra),
            shared_ioc_score=round(shared_ioc_score, 4),
            first_seen=first_seen,
            last_seen=last_seen,
            evolution_days=evolution,
            rationale=rationale,
        )

    def _campaigns(self) -> tuple[GraphNode, ...]:
        return tuple(n for n in self._query.all_nodes() if n.node_type is NodeType.CAMPAIGN)

    def _infrastructure_ids(self, campaign_id: str) -> set[str]:
        reachable = self._query.reachable(campaign_id, max_depth=_CAMPAIGN_DEPTH)
        return {n.node_id for n in reachable if n.node_type in _INFRA_TYPES}

    def _evolution(self, campaign_id: str) -> tuple[str, str, float]:
        stamps = sorted(e.timestamp for e in self._query.edges_of(campaign_id) if e.timestamp)
        if not stamps:
            return "", "", 0.0
        first, last = stamps[0], stamps[-1]
        try:
            delta = datetime.fromisoformat(last) - datetime.fromisoformat(first)
            days = round(delta.total_seconds() / 86400.0, 3)
        except ValueError:
            days = 0.0
        return first, last, days

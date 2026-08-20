"""Analyst Recommendation Engine (M11 Phase D).

Deterministic, explainable recommendations composed over the Phase A/B/C
services (graph analytics, IOC/campaign intelligence, threat scoring). It ranks
and selects subjects using those services' own scores and carries their rationale
forward, so no scoring logic is duplicated here.
"""

from __future__ import annotations

from core.domain.recommendation_view import Recommendation, RecommendationSet
from core.interfaces.logger import ILogger
from services.analytics.campaign_intelligence import CampaignIntelligenceService
from services.analytics.graph_analytics import GraphAnalyticsService
from services.analytics.ioc_intelligence import IOCIntelligenceService
from services.analytics.observability import MeteredService, tracked
from services.analytics.threat_scoring import ThreatScoringService

_DEFAULT_TOP = 5
_MIN_REUSE = 2


class RecommendationService(MeteredService):
    """Deterministic analyst recommendations reusing the analytics engine."""

    def __init__(
        self,
        analytics: GraphAnalyticsService,
        ioc: IOCIntelligenceService,
        campaign: CampaignIntelligenceService,
        scoring: ThreatScoringService,
        logger: ILogger,
    ) -> None:
        """Initialize the recommendation service.

        Args:
            analytics: Graph analytics engine (Phase A).
            ioc: IOC intelligence service (Phase B).
            campaign: Campaign intelligence service (Phase B).
            scoring: Threat scoring service (Phase B).
            logger: Injected logger.
        """
        super().__init__()
        self._analytics = analytics
        self._ioc = ioc
        self._campaign = campaign
        self._scoring = scoring
        self._logger = logger

    # --- individual recommendations -------------------------------------

    @tracked
    def next_investigation(self) -> Recommendation | None:
        """The artifact an analyst should investigate next (highest urgency)."""
        ranked = self._scoring.rank(top=1)
        if not ranked:
            return None
        top = ranked[0]
        return Recommendation(
            kind="next_investigation",
            title=f"Investigate {top.label or top.artifact_id}",
            subject_id=top.artifact_id,
            subject_type="artifact",
            priority=top.analyst_urgency,
            rationale=("Highest analyst-urgency artifact.", *top.rationale),
        )

    @tracked
    def highest_priority_ioc(self) -> Recommendation | None:
        """The IOC to prioritise (highest confidence and reuse)."""
        ranked = self._ioc.rank(top=1)
        if not ranked:
            return None
        top = ranked[0]
        return Recommendation(
            kind="highest_priority_ioc",
            title=f"Prioritise IOC {top.label or top.ioc_id}",
            subject_id=top.ioc_id,
            subject_type="ioc",
            priority=top.confidence,
            rationale=("Highest-confidence, most-reused IOC.", *top.rationale),
        )

    @tracked
    def highest_risk_campaign(self) -> Recommendation | None:
        """The campaign posing the greatest risk (largest, most connected)."""
        ranked = self._campaign.rank(top=1)
        if not ranked:
            return None
        top = ranked[0]
        priority = min(1.0, top.artifact_count / 10.0)
        return Recommendation(
            kind="highest_risk_campaign",
            title=f"Review campaign {top.label or top.campaign_id}",
            subject_id=top.campaign_id,
            subject_type="campaign",
            priority=round(priority, 4),
            rationale=("Largest, most connected campaign.", *top.rationale),
        )

    @tracked
    def most_suspicious_relationship(self) -> Recommendation | None:
        """The most suspicious shared-infrastructure relationship."""
        iocs = self._ioc.rank(top=1)
        if not iocs or iocs[0].frequency < _MIN_REUSE:
            return None
        top = iocs[0]
        return Recommendation(
            kind="most_suspicious_relationship",
            title=f"Shared infrastructure via {top.label or top.ioc_id}",
            subject_id=top.ioc_id,
            subject_type="ioc",
            priority=top.confidence,
            rationale=(
                f"IOC reused across {top.frequency} artifacts — a pivot point.",
                *top.rationale,
            ),
        )

    # --- ordered recommendations ----------------------------------------

    @tracked
    def containment_order(self, *, top: int = _DEFAULT_TOP) -> tuple[Recommendation, ...]:
        """Suggested containment order (highest exposure first)."""
        scores = sorted(
            self._scoring.rank(top=top * 2),
            key=lambda s: (-s.exposure, -s.priority, s.artifact_id),
        )[:top]
        return tuple(
            Recommendation(
                kind="containment_order",
                title=f"Contain {s.label or s.artifact_id}",
                subject_id=s.artifact_id,
                subject_type="artifact",
                priority=s.exposure,
                rationale=(f"Rank {rank}: highest exposure first.", *s.rationale),
            )
            for rank, s in enumerate(scores, start=1)
        )

    @tracked
    def investigation_sequence(self, *, top: int = _DEFAULT_TOP) -> tuple[Recommendation, ...]:
        """Suggested investigation sequence (highest urgency first)."""
        scores = self._scoring.rank(top=top)
        return tuple(
            Recommendation(
                kind="investigation_sequence",
                title=f"Step {rank}: {s.label or s.artifact_id}",
                subject_id=s.artifact_id,
                subject_type="artifact",
                priority=s.analyst_urgency,
                rationale=(f"Sequence position {rank} by analyst urgency.", *s.rationale),
            )
            for rank, s in enumerate(scores, start=1)
        )

    # --- aggregate -------------------------------------------------------

    @tracked
    def recommended_actions(self) -> RecommendationSet:
        """The headline recommendations for the SOC dashboard."""
        singles = [
            self.next_investigation(),
            self.highest_priority_ioc(),
            self.highest_risk_campaign(),
            self.most_suspicious_relationship(),
        ]
        present = [r for r in singles if r is not None]
        present.sort(key=lambda r: (-r.priority, r.kind))
        return RecommendationSet(recommendations=tuple(present))

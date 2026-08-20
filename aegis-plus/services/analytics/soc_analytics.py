"""SOC Analytics Overview Service (M11 Phase E).

Aggregates the Phase A-D analytics/intelligence services into a single, cached-free
overview for the SOC dashboard's advanced widgets. It reuses each service's own
ranked output and adds only presentation-level bucketing; it computes no scores of
its own.
"""

from __future__ import annotations

from core.domain.attack_view import CompromisePath
from core.domain.soc_analytics_view import AnalyticsOverview
from core.interfaces.logger import ILogger
from services.analytics.attack_analysis import AttackAnalysisService
from services.analytics.campaign_intelligence import CampaignIntelligenceService
from services.analytics.ioc_intelligence import IOCIntelligenceService
from services.analytics.observability import MeteredService, tracked
from services.analytics.recommendations import RecommendationService
from services.analytics.threat_scoring import ThreatScoringService

_DEFAULT_TOP = 5
_DISTRIBUTION_SAMPLE = 100
_MIN_PATH_MEMBERS = 2
# Severity buckets (lower bound, label), highest first.
_SEVERITY_BUCKETS = (
    (0.8, "critical"),
    (0.6, "high"),
    (0.4, "medium"),
    (0.0, "low"),
)


class AnalyticsOverviewService(MeteredService):
    """Aggregate SOC analytics overview built from the M11 engine."""

    def __init__(
        self,
        scoring: ThreatScoringService,
        campaign: CampaignIntelligenceService,
        ioc: IOCIntelligenceService,
        attack: AttackAnalysisService,
        recommendations: RecommendationService,
        logger: ILogger,
    ) -> None:
        """Initialize the SOC analytics overview service.

        Args:
            scoring: Threat scoring service (Phase B).
            campaign: Campaign intelligence service (Phase B).
            ioc: IOC intelligence service (Phase B).
            attack: Attack analysis service (Phase C).
            recommendations: Recommendation service (Phase D).
            logger: Injected logger.
        """
        super().__init__()
        self._scoring = scoring
        self._campaign = campaign
        self._ioc = ioc
        self._attack = attack
        self._recommendations = recommendations
        self._logger = logger

    @tracked
    def overview(self, *, top: int = _DEFAULT_TOP) -> AnalyticsOverview:
        """Build the aggregate analytics overview for the SOC dashboard."""
        return AnalyticsOverview(
            threat_priorities=self._scoring.rank(top=top),
            emerging_campaigns=self._campaign.rank(top=top),
            ioc_trends=self._ioc.rank(top=top),
            infrastructure_reuse=self._attack.infrastructure_clusters(top=top),
            critical_attack_paths=self._critical_paths(top=top),
            threat_distribution=self._threat_distribution(),
            recommendations=self._recommendations.recommended_actions().recommendations,
        )

    # --- internals -------------------------------------------------------

    def _critical_paths(self, *, top: int) -> tuple[CompromisePath, ...]:
        paths: list[CompromisePath] = []
        for cluster in self._attack.infrastructure_clusters(top=top):
            members = cluster.member_ids
            if len(members) >= _MIN_PATH_MEMBERS:
                paths.extend(self._attack.compromise_paths(members[0], members[1]))
        return tuple(paths[:top])

    def _threat_distribution(self) -> tuple[tuple[str, int], ...]:
        scores = self._scoring.rank(top=_DISTRIBUTION_SAMPLE)
        counts = {label: 0 for _, label in _SEVERITY_BUCKETS}
        for score in scores:
            counts[_bucket(score.severity)] += 1
        return tuple((label, counts[label]) for _, label in _SEVERITY_BUCKETS)


def _bucket(severity: float) -> str:
    for lower, label in _SEVERITY_BUCKETS:
        if severity >= lower:
            return label
    return "low"

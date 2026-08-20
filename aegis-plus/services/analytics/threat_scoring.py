"""Threat Scoring Service (M11 Phase B).

Deterministic, explainable threat scoring for artifact nodes. Combines the
artifact's own risk (severity), how far it reaches in the graph (exposure / blast
radius, reused from the Phase A analytics engine), and its evidential support
(confidence) into priority and analyst-urgency scores. Every score carries a
plain-language rationale. No AI, no persistence.
"""

from __future__ import annotations

from core.domain.graph import GraphNode, NodeType
from core.domain.intelligence_view import ThreatScore
from core.interfaces.logger import ILogger
from services.analytics.graph_analytics import GraphAnalyticsService
from services.analytics.observability import MeteredService, tracked
from services.graph.query import GraphQueryService

_DEFAULT_TOP = 10
_ARTIFACT_TYPES = frozenset({NodeType.FILE, NodeType.URL, NodeType.EMAIL, NodeType.ARTIFACT})

# Priority = severity and exposure; urgency also folds in confidence.
_W_PRIORITY_SEVERITY = 0.6
_W_PRIORITY_EXPOSURE = 0.4
_W_URGENCY_SEVERITY = 0.5
_W_URGENCY_EXPOSURE = 0.3
_W_URGENCY_CONFIDENCE = 0.2
_CONFIDENCE_BASE = 0.5
_CONFIDENCE_PER_IOC = 0.1
_CONFIDENCE_THREAT_BONUS = 0.2


class ThreatScoringService(MeteredService):
    """Deterministic, explainable threat scoring for artifacts."""

    def __init__(
        self,
        query: GraphQueryService,
        analytics: GraphAnalyticsService,
        logger: ILogger,
    ) -> None:
        """Initialize the threat scoring service.

        Args:
            query: The graph query service.
            analytics: The Phase A analytics engine (reused for blast radius).
            logger: Injected logger.
        """
        super().__init__()
        self._query = query
        self._analytics = analytics
        self._logger = logger

    @tracked
    def score(self, artifact_id: str) -> ThreatScore:
        """Compute an explainable threat score for an artifact."""
        return self._compute(artifact_id)

    @tracked
    def rank(self, *, top: int = _DEFAULT_TOP) -> tuple[ThreatScore, ...]:
        """Rank artifacts by analyst urgency then priority (deterministic)."""
        scores = [self._compute(n.node_id) for n in self._artifacts()]
        scores.sort(key=lambda s: (-s.analyst_urgency, -s.priority, s.artifact_id))
        return tuple(scores[:top])

    # --- internals -------------------------------------------------------

    def _compute(self, artifact_id: str) -> ThreatScore:
        node = self._query.lookup(artifact_id)
        label = node.display_name if node else artifact_id
        severity = _risk(node.metadata.get("risk_score", "")) if node else 0.0

        neighbors = self._query.neighbors(artifact_id)
        ioc_count = sum(1 for n in neighbors if n.node_type is NodeType.IOC)
        has_threat = any(n.node_type is NodeType.THREAT for n in neighbors)

        blast = self._analytics.blast_radius(artifact_id)
        total_nodes = self._query.snapshot().node_count
        exposure = blast.reachable_count / max(total_nodes - 1, 1)
        exposure = _clamp(exposure)

        confidence = _clamp(
            _CONFIDENCE_BASE
            + _CONFIDENCE_PER_IOC * ioc_count
            + (_CONFIDENCE_THREAT_BONUS if has_threat else 0.0)
        )
        priority = _clamp(_W_PRIORITY_SEVERITY * severity + _W_PRIORITY_EXPOSURE * exposure)
        urgency = _clamp(
            _W_URGENCY_SEVERITY * severity
            + _W_URGENCY_EXPOSURE * exposure
            + _W_URGENCY_CONFIDENCE * confidence
        )
        rationale = (
            f"Severity {severity * 100:.0f}% (artifact risk)",
            f"Exposure {exposure * 100:.0f}% (blast radius {blast.reachable_count})",
            f"Confidence {confidence * 100:.0f}% "
            f"({ioc_count} IOC(s){', threat-linked' if has_threat else ''})",
            f"Priority {priority * 100:.0f}%, urgency {urgency * 100:.0f}%",
        )
        return ThreatScore(
            artifact_id=artifact_id,
            label=label,
            severity=round(severity, 4),
            confidence=round(confidence, 4),
            exposure=round(exposure, 4),
            blast_radius=blast.reachable_count,
            priority=round(priority, 4),
            analyst_urgency=round(urgency, 4),
            rationale=rationale,
        )

    def _artifacts(self) -> tuple[GraphNode, ...]:
        return tuple(n for n in self._query.all_nodes() if n.node_type in _ARTIFACT_TYPES)


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _risk(raw: str) -> float:
    try:
        return _clamp(float(raw))
    except (TypeError, ValueError):
        return 0.0

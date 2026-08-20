"""URL scan aggregate.

An :class:`UrlScan` records a URL analysis: the submitted URL, the verdict and
scores, the extracted features, the explainable contributions, and - as of the
Intelligence Engine - the primary threat category, evidence strength, and the
per-source intelligence summary. It is the persisted aggregate for the URL
Analysis vertical.
"""

from __future__ import annotations

from datetime import datetime

from core.domain.analysis import FeatureContribution, FeatureValue, UrlAnalysis, Verdict
from core.domain.intelligence import IntelligenceReport, SourceScore, ThreatCategory
from core.domain.url import Url
from core.domain.value_objects import EntityId
from core.entities.base import AggregateRoot


class UrlScan(AggregateRoot):
    """A persisted URL analysis result."""

    def __init__(  # noqa: PLR0913 - a data-carrying aggregate with many persisted fields
        self,
        *,
        url: str,
        verdict: Verdict,
        threat_score: float,
        confidence: float,
        features: dict[str, FeatureValue],
        contributions: tuple[FeatureContribution, ...],
        category: ThreatCategory = ThreatCategory.NONE,
        evidence_strength: float = 0.0,
        sources: tuple[SourceScore, ...] = (),
        actor: str | None = None,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize a URL scan record.

        Args:
            url: The analyzed (normalized) URL.
            verdict: The classification outcome.
            threat_score: The threat score in ``[0, 1]``.
            confidence: The model's confidence in ``[0, 1]``.
            features: The extracted feature values.
            contributions: The explainable contributions.
            category: The primary threat category.
            evidence_strength: Combined evidence strength in ``[0, 1]``.
            sources: Per-source intelligence summary.
            actor: Identifier of the requester, if known.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp.
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        self.url = url
        self.verdict = verdict
        self.threat_score = threat_score
        self.confidence = confidence
        self.features = features
        self.contributions = contributions
        self.category = category
        self.evidence_strength = evidence_strength
        self.sources = sources
        self.actor = actor

    @classmethod
    def from_analysis(cls, url: Url, analysis: UrlAnalysis, *, actor: str | None = None) -> UrlScan:
        """Build a scan record from a URL and a single-source analysis."""
        return cls(
            url=str(url),
            verdict=analysis.verdict,
            threat_score=analysis.threat_score,
            confidence=analysis.confidence,
            features=analysis.features,
            contributions=analysis.contributions,
            actor=actor,
        )

    @classmethod
    def from_report(
        cls, url: Url, report: IntelligenceReport, *, actor: str | None = None
    ) -> UrlScan:
        """Build a scan record from a combined intelligence report."""
        return cls(
            url=str(url),
            verdict=report.verdict,
            threat_score=report.risk_score,
            confidence=report.confidence,
            features=report.features,
            contributions=report.triggered_contributions,
            category=report.primary_category,
            evidence_strength=report.evidence_strength,
            sources=report.source_scores,
            actor=actor,
        )

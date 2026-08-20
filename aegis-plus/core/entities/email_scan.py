"""Email scan aggregate.

An :class:`EmailScan` records the result of analyzing an email: the sender and
subject, the verdict and scores, the primary threat category, evidence strength,
the explainable contributions, the per-source intelligence summary, and how many
embedded URLs were found and flagged. It is the persisted aggregate for the Email
Analysis vertical, mirroring :class:`UrlScan`.
"""

from __future__ import annotations

from datetime import datetime

from core.domain.analysis import FeatureContribution, Verdict
from core.domain.email import EmailMessage
from core.domain.intelligence import IntelligenceReport, SourceScore, ThreatCategory
from core.domain.value_objects import EntityId
from core.entities.base import AggregateRoot


class EmailScan(AggregateRoot):
    """A persisted email analysis result."""

    def __init__(  # noqa: PLR0913 - a data-carrying aggregate with many persisted fields
        self,
        *,
        sender: str,
        subject: str,
        verdict: Verdict,
        threat_score: float,
        confidence: float,
        category: ThreatCategory,
        evidence_strength: float,
        contributions: tuple[FeatureContribution, ...],
        sources: tuple[SourceScore, ...],
        url_count: int = 0,
        malicious_url_count: int = 0,
        actor: str | None = None,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize an email scan record.

        Args:
            sender: The sender address.
            subject: The email subject.
            verdict: The classification outcome.
            threat_score: The threat score in ``[0, 1]``.
            confidence: Combined confidence in ``[0, 1]``.
            category: The primary threat category.
            evidence_strength: Combined evidence strength in ``[0, 1]``.
            contributions: The explainable contributions.
            sources: Per-source intelligence summary.
            url_count: Number of embedded URLs found.
            malicious_url_count: Number of embedded URLs flagged malicious.
            actor: Identifier of the requester, if known.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp.
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        self.sender = sender
        self.subject = subject
        self.verdict = verdict
        self.threat_score = threat_score
        self.confidence = confidence
        self.category = category
        self.evidence_strength = evidence_strength
        self.contributions = contributions
        self.sources = sources
        self.url_count = url_count
        self.malicious_url_count = malicious_url_count
        self.actor = actor

    @classmethod
    def from_report(
        cls,
        email: EmailMessage,
        report: IntelligenceReport,
        *,
        url_count: int = 0,
        malicious_url_count: int = 0,
        actor: str | None = None,
    ) -> EmailScan:
        """Build an email scan record from a combined intelligence report."""
        return cls(
            sender=email.sender.address,
            subject=email.subject,
            verdict=report.verdict,
            threat_score=report.risk_score,
            confidence=report.confidence,
            category=report.primary_category,
            evidence_strength=report.evidence_strength,
            contributions=report.triggered_contributions,
            sources=report.source_scores,
            url_count=url_count,
            malicious_url_count=malicious_url_count,
            actor=actor,
        )

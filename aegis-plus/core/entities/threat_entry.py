"""Threat intelligence entry aggregate.

A :class:`ThreatEntry` is a blacklisted artifact and its detection metadata. It
is deliberately artifact-agnostic in shape (URL now; email, file, and network
indicators later) so the Threat Intelligence module is a reusable foundation for
future detection verticals.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.constants import ArtifactType, BlockSource
from core.domain.analysis import FeatureContribution, UrlAnalysis, Verdict
from core.domain.intelligence import IntelligenceReport
from core.domain.url import Url
from core.domain.value_objects import EntityId
from core.entities.base import AggregateRoot


class ThreatEntry(AggregateRoot):
    """A blacklisted artifact with detection history."""

    def __init__(  # noqa: PLR0913 - a data-carrying aggregate with many persisted fields
        self,
        *,
        artifact_hash: str,
        artifact: str,
        verdict: Verdict,
        artifact_type: ArtifactType = ArtifactType.URL,
        risk_score: float,
        confidence: float,
        indicators: tuple[FeatureContribution, ...],
        first_detected: datetime,
        last_detected: datetime,
        detection_count: int = 1,
        blocked: bool = True,
        block_source: BlockSource = BlockSource.AI,
        notes: str | None = None,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize a threat entry.

        Args:
            artifact_hash: Stable hash of the artifact (used for fast lookup).
            artifact: The artifact itself (URL, or an email identity).
            artifact_type: The kind of artifact (URL or email).
            verdict: The classification that caused the block.
            risk_score: Threat score in ``[0, 1]``.
            confidence: Model confidence in ``[0, 1]``.
            indicators: Explainable detection indicators.
            first_detected: When the artifact was first detected.
            last_detected: When the artifact was most recently detected.
            detection_count: Number of times detected.
            blocked: Whether the artifact is currently blocked.
            block_source: Who/what created the block.
            notes: Optional free-form notes.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp.
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        self.artifact_hash = artifact_hash
        self.artifact = artifact
        self.artifact_type = artifact_type
        self.verdict = verdict
        self.risk_score = risk_score
        self.confidence = confidence
        self.indicators = indicators
        self.first_detected = first_detected
        self.last_detected = last_detected
        self.detection_count = detection_count
        self.blocked = blocked
        self.block_source = block_source
        self.notes = notes

    @classmethod
    def from_analysis(
        cls,
        url: Url,
        analysis: UrlAnalysis,
        *,
        source: BlockSource = BlockSource.AI,
    ) -> ThreatEntry:
        """Create a blacklist entry from a URL analysis.

        Args:
            url: The analyzed URL.
            analysis: The analysis result.
            source: The block source.

        Returns:
            A new :class:`ThreatEntry`.
        """
        now = datetime.now(UTC)
        return cls(
            artifact_hash=url.fingerprint,
            artifact=str(url),
            verdict=analysis.verdict,
            risk_score=analysis.threat_score,
            confidence=analysis.confidence,
            indicators=analysis.triggered_contributions,
            first_detected=now,
            last_detected=now,
            detection_count=1,
            blocked=True,
            block_source=source,
        )

    @classmethod
    def from_report(
        cls,
        artifact_hash: str,
        artifact: str,
        report: IntelligenceReport,
        *,
        artifact_type: ArtifactType,
        source: BlockSource = BlockSource.AI,
    ) -> ThreatEntry:
        """Create a blacklist entry from any intelligence report.

        The generic factory used by every detection vertical (URL, email, and
        future artifact types), so Threat Intelligence stays a shared foundation.

        Args:
            artifact_hash: Stable hash of the artifact.
            artifact: The artifact identity (URL string or email identity).
            report: The combined intelligence report.
            artifact_type: The kind of artifact.
            source: The block source.

        Returns:
            A new :class:`ThreatEntry`.
        """
        now = datetime.now(UTC)
        return cls(
            artifact_hash=artifact_hash,
            artifact=artifact,
            artifact_type=artifact_type,
            verdict=report.verdict,
            risk_score=report.risk_score,
            confidence=report.confidence,
            indicators=report.triggered_contributions,
            first_detected=now,
            last_detected=now,
            detection_count=1,
            blocked=True,
            block_source=source,
        )

    def register_detection(self) -> None:
        """Record a repeat detection: bump the count and last-seen time."""
        self.detection_count += 1
        self.last_detected = datetime.now(UTC)
        self.touch()

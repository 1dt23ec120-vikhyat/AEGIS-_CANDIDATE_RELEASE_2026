"""File scan aggregate.

A :class:`FileScan` records the result of analyzing a file: its identity
(fingerprints), type and size, entropy, the verdict and scores, the primary
threat category, evidence strength, the explainable contributions, the per-source
intelligence summary, extracted indicator counts, and how many embedded URLs were
found and flagged. It is the persisted aggregate for the File Analysis vertical,
mirroring :class:`UrlScan` and :class:`EmailScan`.

Consistent with the approved design, no raw file bytes are held or persisted -
only fingerprints, metadata, and derived findings.
"""

from __future__ import annotations

from datetime import datetime

from core.domain.analysis import FeatureContribution, Verdict
from core.domain.file import FingerprintSet
from core.domain.intelligence import IntelligenceReport, SourceScore, ThreatCategory
from core.domain.value_objects import EntityId
from core.entities.base import AggregateRoot


class FileScan(AggregateRoot):
    """A persisted file analysis result."""

    def __init__(  # noqa: PLR0913 - a data-carrying aggregate with many persisted fields
        self,
        *,
        filename: str,
        size: int,
        fingerprints: FingerprintSet,
        file_kind: str,
        detected_mime: str,
        entropy: float,
        verdict: Verdict,
        threat_score: float,
        confidence: float,
        category: ThreatCategory,
        evidence_strength: float,
        contributions: tuple[FeatureContribution, ...],
        sources: tuple[SourceScore, ...],
        indicator_count: int = 0,
        url_count: int = 0,
        malicious_url_count: int = 0,
        actor: str | None = None,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize a file scan record.

        Args:
            filename: The original (sanitized) filename.
            size: The file size in bytes.
            fingerprints: The computed fingerprint set (SHA-256/SHA-1/MD5).
            file_kind: The coarse file kind (executable, document, ...).
            detected_mime: The MIME type detected from content.
            entropy: Shannon entropy in bits per byte.
            verdict: The classification outcome.
            threat_score: The threat score in ``[0, 1]``.
            confidence: Combined confidence in ``[0, 1]``.
            category: The primary threat category.
            evidence_strength: Combined evidence strength in ``[0, 1]``.
            contributions: The explainable contributions.
            sources: Per-source intelligence summary.
            indicator_count: Number of extracted indicators of compromise.
            url_count: Number of embedded URLs found.
            malicious_url_count: Number of embedded URLs flagged malicious.
            actor: Identifier of the requester, if known.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp.
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        self.filename = filename
        self.size = size
        self.fingerprints = fingerprints
        self.file_kind = file_kind
        self.detected_mime = detected_mime
        self.entropy = entropy
        self.verdict = verdict
        self.threat_score = threat_score
        self.confidence = confidence
        self.category = category
        self.evidence_strength = evidence_strength
        self.contributions = contributions
        self.sources = sources
        self.indicator_count = indicator_count
        self.url_count = url_count
        self.malicious_url_count = malicious_url_count
        self.actor = actor

    @property
    def sha256(self) -> str:
        """The SHA-256 digest, the file's primary identity."""
        return self.fingerprints.sha256

    @classmethod
    def from_report(  # noqa: PLR0913 - constructs an aggregate with many fields
        cls,
        *,
        filename: str,
        size: int,
        fingerprints: FingerprintSet,
        file_kind: str,
        detected_mime: str,
        entropy: float,
        report: IntelligenceReport,
        indicator_count: int = 0,
        url_count: int = 0,
        malicious_url_count: int = 0,
        actor: str | None = None,
    ) -> FileScan:
        """Build a file scan record from a combined intelligence report."""
        return cls(
            filename=filename,
            size=size,
            fingerprints=fingerprints,
            file_kind=file_kind,
            detected_mime=detected_mime,
            entropy=entropy,
            verdict=report.verdict,
            threat_score=report.risk_score,
            confidence=report.confidence,
            category=report.primary_category,
            evidence_strength=report.evidence_strength,
            contributions=report.triggered_contributions,
            sources=report.source_scores,
            indicator_count=indicator_count,
            url_count=url_count,
            malicious_url_count=malicious_url_count,
            actor=actor,
        )

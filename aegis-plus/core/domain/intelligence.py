"""URL intelligence domain model.

The evidence-based result of hybrid URL analysis: multiple independent sources
(machine learning, heuristics, reputation, threat intelligence, domain
intelligence) each contribute a piece of :class:`Evidence`, and a pure policy
combines them into an :class:`IntelligenceReport`. This is framework-independent
domain logic - the gathering of evidence (which calls out to ports) lives in the
application layer, while the combination policy lives here.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from enum import Enum

from core.domain.analysis import (
    FeatureContribution,
    FeatureValue,
    UrlAnalysis,
    Verdict,
)
from core.domain.value_objects import ValueObject


class EvidenceSource(str, Enum):
    """An independent source of detection evidence."""

    ML = "ml"
    HEURISTIC = "heuristic"
    REPUTATION = "reputation"
    THREAT_INTEL = "threat_intel"
    DOMAIN = "domain"
    # Email evidence sources.
    HEADER = "header"
    AUTHENTICATION = "authentication"
    SENDER = "sender"
    LANGUAGE = "language"
    ATTACHMENT = "attachment"
    URL = "url"
    # File evidence sources.
    FILE_STRUCTURE = "file_structure"
    FILE_ENTROPY = "file_entropy"
    FILE_METADATA = "file_metadata"
    FILE_MACRO = "file_macro"
    FILE_SCRIPT = "file_script"
    FILE_ARCHIVE = "file_archive"
    FILE_EXECUTABLE = "file_executable"


class ThreatCategory(str, Enum):
    """The primary category of a detected threat."""

    NONE = "none"
    PHISHING = "phishing"
    MALWARE = "malware"
    DECEPTIVE_DOMAIN = "deceptive_domain"
    SUSPICIOUS_STRUCTURE = "suspicious_structure"
    REPUTATION_FLAGGED = "reputation_flagged"
    # Email threat categories.
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    MALWARE_DELIVERY = "malware_delivery"
    BRAND_IMPERSONATION = "brand_impersonation"
    SUSPICIOUS_SENDER = "suspicious_sender"
    SPAM = "spam"
    # File threat categories.
    MALICIOUS_DOCUMENT = "malicious_document"
    MALICIOUS_SCRIPT = "malicious_script"
    MALICIOUS_ARCHIVE = "malicious_archive"
    SUSPICIOUS_EXECUTABLE = "suspicious_executable"


@dataclass(frozen=True, slots=True)
class Evidence(ValueObject):
    """One source's contribution to the overall verdict.

    The ``provider_name``, ``provider_version``, and ``execution_ms`` fields
    expose provider diagnostics for future monitoring dashboards (VirusTotal,
    YARA, Sandbox) without requiring a contract change. ``technique_ids``
    prepares for MITRE ATT&CK enrichment.
    """

    source: EvidenceSource
    risk: float
    confidence: float
    weight: float
    rationale: str
    category: ThreatCategory = ThreatCategory.NONE
    contributions: tuple[FeatureContribution, ...] = ()
    available: bool = True
    provider_name: str = ""
    provider_version: str = ""
    execution_ms: float = 0.0
    technique_ids: tuple[str, ...] = ()

    @property
    def weighted_risk(self) -> float:
        """The risk scaled by this source's weight."""
        return self.risk * self.weight


@dataclass(frozen=True, slots=True)
class SourceScore(ValueObject):
    """A compact, persistable summary of one source's contribution."""

    source: EvidenceSource
    risk: float
    confidence: float
    available: bool
    rationale: str


@dataclass(frozen=True, slots=True)
class IntelligenceReport(ValueObject):
    """The combined result of hybrid URL intelligence."""

    verdict: Verdict
    risk_score: float
    confidence: float
    evidence_strength: float
    primary_category: ThreatCategory
    evidences: tuple[Evidence, ...]
    contributions: tuple[FeatureContribution, ...]
    features: dict[str, FeatureValue]

    @property
    def risk_percent(self) -> int:
        """The risk score as an integer percentage (0-100)."""
        return round(self.risk_score * 100)

    @property
    def triggered_contributions(self) -> tuple[FeatureContribution, ...]:
        """Only the contributions that fired, most significant first."""
        fired = [c for c in self.contributions if c.triggered]
        return tuple(sorted(fired, key=lambda c: c.weight, reverse=True))

    @property
    def available_sources(self) -> tuple[Evidence, ...]:
        """The evidences from sources that were able to run."""
        return tuple(e for e in self.evidences if e.available)

    @property
    def source_scores(self) -> tuple[SourceScore, ...]:
        """A compact per-source summary for persistence and display."""
        return tuple(
            SourceScore(
                source=e.source,
                risk=e.risk,
                confidence=e.confidence,
                available=e.available,
                rationale=e.rationale,
            )
            for e in self.evidences
        )

    def to_analysis(self) -> UrlAnalysis:
        """Project the report onto the simpler :class:`UrlAnalysis` shape."""
        return UrlAnalysis(
            verdict=self.verdict,
            threat_score=self.risk_score,
            confidence=self.confidence,
            features=self.features,
            contributions=self.contributions,
        )


_MIN_PEAK_CONFIDENCE = 0.5


def _verdict_for(score: float, suspicious_threshold: float, phishing_threshold: float) -> Verdict:
    if score >= phishing_threshold:
        return Verdict.PHISHING
    if score >= suspicious_threshold:
        return Verdict.SUSPICIOUS
    return Verdict.LEGITIMATE


def combine_evidence(
    evidences: tuple[Evidence, ...],
    *,
    suspicious_threshold: float,
    phishing_threshold: float,
    fallback_category: ThreatCategory = ThreatCategory.PHISHING,
    features: dict[str, FeatureValue] | None = None,
) -> IntelligenceReport:
    """Combine multi-source evidence into a single intelligence report.

    The risk is a weight-normalized blend of the available sources; confidence is
    a coverage-scaled blend of source confidences; and evidence strength captures
    both how many sources ran and how strongly they agree. Unavailable sources
    (e.g. a disabled or unreachable provider) are excluded, so the engine degrades
    gracefully.

    Args:
        evidences: The gathered evidence from all sources.
        suspicious_threshold: Score at/above which the verdict is suspicious.
        phishing_threshold: Score at/above which the verdict is phishing.
        fallback_category: Category used when a malicious verdict is driven only
            by category-neutral evidence.
        features: The underlying feature values (carried onto the report).

    Returns:
        The combined :class:`IntelligenceReport`.
    """
    feature_map: dict[str, FeatureValue] = dict(features or {})
    available = [e for e in evidences if e.available and e.weight > 0]

    if not available:
        return IntelligenceReport(
            verdict=Verdict.LEGITIMATE,
            risk_score=0.0,
            confidence=0.0,
            evidence_strength=0.0,
            primary_category=ThreatCategory.NONE,
            evidences=evidences,
            contributions=(),
            features=feature_map,
        )

    total_weight = sum(e.weight for e in available)
    weighted_avg = sum(e.weighted_risk for e in available) / total_weight
    # A single sufficiently-confident source can carry the verdict on its own
    # risk, so a strong detection is not diluted by sources that found nothing;
    # corroborating sources still raise a borderline case via the consensus.
    confident = [e for e in available if e.confidence >= _MIN_PEAK_CONFIDENCE]
    peak = max((e.risk for e in confident), default=0.0)
    risk_score = round(max(weighted_avg, peak), 4)

    coverage = len(available) / len(evidences)
    confidence_blend = sum(e.confidence * e.weight for e in available) / total_weight
    confidence = round(confidence_blend * (0.6 + 0.4 * coverage), 4)

    risks = [e.risk for e in available]
    spread = statistics.pstdev(risks) if len(risks) > 1 else 0.0
    agreement = max(0.0, 1.0 - 2.0 * spread)
    evidence_strength = round(coverage * (0.5 + 0.5 * agreement), 4)

    verdict = _verdict_for(risk_score, suspicious_threshold, phishing_threshold)

    ranked = sorted(available, key=lambda e: e.risk * e.confidence, reverse=True)
    primary = next(
        (e.category for e in ranked if e.category is not ThreatCategory.NONE and e.risk > 0),
        ThreatCategory.NONE,
    )
    if primary is ThreatCategory.NONE and verdict is not Verdict.LEGITIMATE:
        # Risk came entirely from category-neutral evidence (for example an
        # authentication failure). A malicious verdict must still carry a
        # meaningful category, so fall back rather than reporting "none".
        primary = fallback_category

    merged: dict[str, FeatureContribution] = {}
    for evidence in ranked:
        for contribution in evidence.contributions:
            existing = merged.get(contribution.feature)
            if existing is None or contribution.weight > existing.weight:
                merged[contribution.feature] = contribution
    contributions = tuple(sorted(merged.values(), key=lambda c: c.weight, reverse=True))

    return IntelligenceReport(
        verdict=verdict,
        risk_score=risk_score,
        confidence=confidence,
        evidence_strength=evidence_strength,
        primary_category=primary,
        evidences=evidences,
        contributions=contributions,
        features=feature_map,
    )

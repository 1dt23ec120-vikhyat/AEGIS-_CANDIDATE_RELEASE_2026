"""Analysis value objects.

The immutable outputs of URL analysis: a verdict, a threat score, the underlying
feature values, and the explainable contributions that justify the score. These
are pure domain values, independent of any model implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from core.domain.value_objects import ValueObject

FeatureValue = float | int | bool


class Verdict(str, Enum):
    """The classification outcome for an analyzed artifact."""

    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


@dataclass(frozen=True, slots=True)
class FeatureContribution(ValueObject):
    """One explainable factor contributing to the threat score.

    The optional ``technique_id`` and ``recommendation`` fields prepare for
    future MITRE ATT&CK mapping and analyst guidance without requiring callers
    to change when they are populated.
    """

    feature: str
    detail: str
    weight: float
    triggered: bool
    technique_id: str = ""
    recommendation: str = ""


@dataclass(frozen=True, slots=True)
class UrlAnalysis(ValueObject):
    """The complete result of analyzing a URL."""

    verdict: Verdict
    threat_score: float
    confidence: float
    features: dict[str, FeatureValue]
    contributions: tuple[FeatureContribution, ...]

    @property
    def risk_percent(self) -> int:
        """The threat score as an integer percentage (0-100)."""
        return round(self.threat_score * 100)

    @property
    def triggered_contributions(self) -> tuple[FeatureContribution, ...]:
        """Only the contributions that fired, most significant first."""
        fired = [c for c in self.contributions if c.triggered]
        return tuple(sorted(fired, key=lambda c: c.weight, reverse=True))

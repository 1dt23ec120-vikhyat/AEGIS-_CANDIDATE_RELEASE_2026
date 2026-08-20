"""Heuristic URL analyzer.

A deterministic, explainable baseline classifier. It scores a URL by combining
weighted risk indicators via a noisy-OR, so the score stays in ``[0, 1]`` and
each fired indicator is reported as an explainable contribution. It implements
the Core ``IUrlAnalyzer`` port, so a trained model (e.g. the LightGBM URL
detector specified in the KB) can replace it without changes elsewhere.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ai.url_analysis.features import extract_features
from core.domain.analysis import (
    FeatureContribution,
    FeatureValue,
    UrlAnalysis,
    Verdict,
)
from core.domain.intelligence import EvidenceSource
from core.domain.url import Url
from core.interfaces import IUrlAnalyzer

_Predicate = Callable[[dict[str, FeatureValue]], bool]

_DEFAULT_SUSPICIOUS_THRESHOLD = 0.35
_DEFAULT_PHISHING_THRESHOLD = 0.70


@dataclass(frozen=True, slots=True)
class _Rule:
    feature: str
    detail: str
    weight: float
    predicate: _Predicate


_RULES: tuple[_Rule, ...] = (
    _Rule(
        "ip_address_used",
        "Host is a raw IP address instead of a domain",
        0.30,
        lambda f: bool(f["ip_address_used"]),
    ),
    _Rule(
        "at_symbol_present",
        "Contains '@', often used to obscure the real host",
        0.22,
        lambda f: bool(f["at_symbol_present"]),
    ),
    _Rule(
        "suspicious_keywords",
        "Contains phishing-associated keywords",
        0.20,
        lambda f: int(f["suspicious_keywords"]) >= 1,
    ),
    _Rule(
        "shortened_url",
        "Uses a URL shortener that hides the destination",
        0.18,
        lambda f: bool(f["shortened_url"]),
    ),
    _Rule("https_used", "Does not use HTTPS", 0.14, lambda f: not bool(f["https_used"])),
    _Rule(
        "subdomain_count",
        "Unusually deep subdomain nesting",
        0.14,
        lambda f: int(f["subdomain_count"]) >= 3,
    ),
    _Rule(
        "encoded_characters",
        "Multiple percent-encoded characters",
        0.10,
        lambda f: int(f["encoded_characters"]) >= 2,
    ),
    _Rule("url_length", "Unusually long URL", 0.08, lambda f: int(f["url_length"]) > 75),
    _Rule("hyphen_count", "Many hyphens in the URL", 0.08, lambda f: int(f["hyphen_count"]) >= 4),
    _Rule(
        "url_entropy",
        "High character entropy (random-looking)",
        0.08,
        lambda f: float(f["url_entropy"]) > 4.0,
    ),
    _Rule(
        "host_digit_ratio",
        "Digit-heavy host name",
        0.08,
        lambda f: float(f["host_digit_ratio"]) > 0.30,
    ),
    _Rule("dot_count", "Many dots in the URL", 0.06, lambda f: int(f["dot_count"]) >= 5),
)


class HeuristicUrlAnalyzer(IUrlAnalyzer):
    """A rule-based, explainable URL analyzer."""

    def __init__(
        self,
        *,
        suspicious_threshold: float = _DEFAULT_SUSPICIOUS_THRESHOLD,
        phishing_threshold: float = _DEFAULT_PHISHING_THRESHOLD,
    ) -> None:
        """Initialize the analyzer.

        Args:
            suspicious_threshold: Score at/above which a URL is suspicious.
            phishing_threshold: Score at/above which a URL is phishing.
        """
        self._suspicious_threshold = suspicious_threshold
        self._phishing_threshold = phishing_threshold

    @property
    def source(self) -> EvidenceSource:
        """Heuristic analysis is its own evidence source."""
        return EvidenceSource.HEURISTIC

    def analyze(self, url: Url) -> UrlAnalysis:
        """Analyze a URL into an explainable result.

        Args:
            url: The validated URL.

        Returns:
            The :class:`UrlAnalysis`.
        """
        features = extract_features(url)

        contributions: list[FeatureContribution] = []
        inverse_product = 1.0
        for rule in _RULES:
            triggered = rule.predicate(features)
            contributions.append(
                FeatureContribution(
                    feature=rule.feature,
                    detail=rule.detail,
                    weight=rule.weight,
                    triggered=triggered,
                )
            )
            if triggered:
                inverse_product *= 1.0 - rule.weight

        threat_score = round(1.0 - inverse_product, 4)
        verdict = self._verdict(threat_score)
        confidence = self._confidence(threat_score, verdict)

        return UrlAnalysis(
            verdict=verdict,
            threat_score=threat_score,
            confidence=confidence,
            features=features,
            contributions=tuple(contributions),
        )

    def _verdict(self, score: float) -> Verdict:
        if score >= self._phishing_threshold:
            return Verdict.PHISHING
        if score >= self._suspicious_threshold:
            return Verdict.SUSPICIOUS
        return Verdict.LEGITIMATE

    def _confidence(self, score: float, verdict: Verdict) -> float:
        """Confidence as distance from the nearest decision boundary."""
        if verdict is Verdict.LEGITIMATE:
            distance = self._suspicious_threshold - score
            span = self._suspicious_threshold
        elif verdict is Verdict.PHISHING:
            distance = score - self._phishing_threshold
            span = 1.0 - self._phishing_threshold
        else:
            midpoint = (self._suspicious_threshold + self._phishing_threshold) / 2
            half = (self._phishing_threshold - self._suspicious_threshold) / 2
            distance = half - abs(score - midpoint)
            span = half
        ratio = distance / span if span > 0 else 0.0
        return round(0.5 + 0.5 * max(0.0, min(1.0, ratio)), 4)

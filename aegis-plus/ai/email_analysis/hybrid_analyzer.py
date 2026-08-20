"""Hybrid email analyzer.

Implements the Core ``IEmailAnalyzer`` port. It gathers evidence from each
configured email evidence provider, appends any caller-supplied evidence (such as
embedded-URL analysis reused from the URL engine, or prior threat intelligence),
re-weights every source from configuration, and combines them with the shared,
pure ``combine_evidence`` policy - the same hybrid engine the URL vertical uses.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from core.domain.email import EmailMessage
from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    IntelligenceReport,
    ThreatCategory,
    combine_evidence,
)
from core.interfaces import IEmailAnalyzer, IEmailEvidenceProvider


class HybridEmailAnalyzer(IEmailAnalyzer):
    """Combines email evidence providers into one intelligence report."""

    def __init__(
        self,
        providers: Sequence[IEmailEvidenceProvider],
        *,
        weights: dict[EvidenceSource, float],
        suspicious_threshold: float,
        phishing_threshold: float,
    ) -> None:
        """Initialize the analyzer.

        Args:
            providers: The email evidence providers to combine.
            weights: Per-source combination weights.
            suspicious_threshold: Score at/above which an email is suspicious.
            phishing_threshold: Score at/above which an email is malicious.
        """
        self._providers = tuple(providers)
        self._weights = weights
        self._suspicious_threshold = suspicious_threshold
        self._phishing_threshold = phishing_threshold

    def analyze(
        self, email: EmailMessage, *, extra_evidence: tuple[Evidence, ...] = ()
    ) -> IntelligenceReport:
        """Analyze an email and return the combined report."""
        gathered = [provider.assess(email) for provider in self._providers]
        gathered.extend(extra_evidence)
        weighted = tuple(replace(e, weight=self._weights.get(e.source, e.weight)) for e in gathered)
        return combine_evidence(
            weighted,
            suspicious_threshold=self._suspicious_threshold,
            phishing_threshold=self._phishing_threshold,
            # A message flagged purely by authentication failure is a spoofing
            # indicator, so label it as a suspicious sender rather than "none".
            fallback_category=ThreatCategory.SUSPICIOUS_SENDER,
        )

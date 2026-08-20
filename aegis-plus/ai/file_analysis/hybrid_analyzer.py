"""Hybrid file analyzer.

Implements the Core ``IFileAnalyzer`` port. It gathers evidence from each
configured artifact evidence provider, appends any caller-supplied evidence (such
as embedded-URL analysis reused from the URL engine, or prior threat
intelligence), re-weights every source from configuration, and combines them with
the shared, pure ``combine_evidence`` policy - the same hybrid engine the URL and
email verticals use.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    IntelligenceReport,
    ThreatCategory,
    combine_evidence,
)
from core.interfaces import AnalyzedArtifact, IArtifactEvidenceProvider, IFileAnalyzer


class HybridFileAnalyzer(IFileAnalyzer):
    """Combines artifact evidence providers into one intelligence report."""

    def __init__(
        self,
        providers: Sequence[IArtifactEvidenceProvider],
        *,
        weights: dict[EvidenceSource, float],
        suspicious_threshold: float,
        phishing_threshold: float,
    ) -> None:
        """Initialize the analyzer.

        Args:
            providers: The artifact evidence providers to combine.
            weights: Per-source combination weights.
            suspicious_threshold: Score at/above which a file is suspicious.
            phishing_threshold: Score at/above which a file is malicious.
        """
        self._providers = tuple(providers)
        self._weights = weights
        self._suspicious_threshold = suspicious_threshold
        self._phishing_threshold = phishing_threshold

    def analyze(
        self, artifact: AnalyzedArtifact, *, extra_evidence: tuple[Evidence, ...] = ()
    ) -> IntelligenceReport:
        """Analyze an artifact and return the combined report."""
        gathered = [provider.assess(artifact) for provider in self._providers]
        gathered.extend(extra_evidence)
        weighted = tuple(replace(e, weight=self._weights.get(e.source, e.weight)) for e in gathered)
        return combine_evidence(
            weighted,
            suspicious_threshold=self._suspicious_threshold,
            phishing_threshold=self._phishing_threshold,
            # A file flagged only by category-neutral evidence (for example high
            # entropy alone) is surfaced under a generic structural category
            # rather than "none"; intent-bearing providers (structure, script,
            # metadata) override this with a specific category when they fire.
            fallback_category=ThreatCategory.SUSPICIOUS_STRUCTURE,
        )

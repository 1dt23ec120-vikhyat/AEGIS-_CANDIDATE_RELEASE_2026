"""Reputation providers.

The default :class:`IReputationProvider` is a graceful no-op: it reports
unavailable evidence so the hybrid engine runs unchanged when no external
reputation source is configured. Network-backed adapters (Safe Browsing,
VirusTotal, PhishTank, OpenPhish) are added behind the same port, remaining
optional and degrading to this behaviour on failure.
"""

from __future__ import annotations

from core.domain.intelligence import Evidence, EvidenceSource, ThreatCategory
from core.domain.url import Url
from core.interfaces import IReputationProvider


class NullReputationProvider(IReputationProvider):
    """A disabled reputation provider that always reports unavailable."""

    @property
    def name(self) -> str:
        """Provider identifier."""
        return "none"

    @property
    def enabled(self) -> bool:
        """Disabled by default."""
        return False

    def check(self, url: Url) -> Evidence:
        """Return unavailable reputation evidence (no source configured)."""
        return Evidence(
            source=EvidenceSource.REPUTATION,
            risk=0.0,
            confidence=0.0,
            weight=1.0,
            rationale="No reputation providers configured",
            category=ThreatCategory.NONE,
            contributions=(),
            available=False,
        )

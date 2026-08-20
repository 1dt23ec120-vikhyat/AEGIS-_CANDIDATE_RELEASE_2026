"""Reputation provider port.

The contract for optional external reputation sources (e.g. Safe Browsing,
VirusTotal). Owned by Core so business logic depends only on this abstraction and
never on a concrete provider. Providers are optional and must degrade gracefully:
when disabled or unreachable they return unavailable evidence rather than raising.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.intelligence import Evidence
from core.domain.url import Url


class IReputationProvider(ABC):
    """Assesses a URL against an external reputation source."""

    @property
    @abstractmethod
    def name(self) -> str:
        """A short identifier for the provider."""

    @property
    @abstractmethod
    def enabled(self) -> bool:
        """Whether the provider is configured and active."""

    @abstractmethod
    def check(self, url: Url) -> Evidence:
        """Return reputation evidence for ``url`` (unavailable on failure)."""

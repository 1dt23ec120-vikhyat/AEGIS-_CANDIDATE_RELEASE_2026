"""Domain intelligence provider port.

The contract for enriching analysis with domain-level intelligence (structure,
homograph/IDN risk, suspicious TLDs, and - via future adapters - WHOIS, DNS, and
certificate metadata). Owned by Core; implementations live in outer layers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.intelligence import Evidence
from core.domain.url import Url


class IDomainIntelligenceProvider(ABC):
    """Assesses the domain of a URL for intelligence signals."""

    @abstractmethod
    def assess(self, url: Url) -> Evidence:
        """Return domain-intelligence evidence for ``url``."""

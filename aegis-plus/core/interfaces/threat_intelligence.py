"""Threat intelligence repository port.

A specialized repository contract for blacklist entries: it extends the generic
repository with the hash lookup and ordered listing the protection use case
requires. Owned by Core so services depend only on the abstraction.
"""

from __future__ import annotations

from abc import abstractmethod

from core.entities.threat_entry import ThreatEntry
from core.interfaces.repository import IRepository


class IThreatIntelligenceRepository(IRepository[ThreatEntry]):
    """Persistence contract for threat intelligence entries."""

    @abstractmethod
    def find_by_hash(self, artifact_hash: str) -> ThreatEntry | None:
        """Return the entry for ``artifact_hash``, or ``None`` if absent."""

    @abstractmethod
    def list_recent(self) -> list[ThreatEntry]:
        """Return all entries, most recently detected first."""

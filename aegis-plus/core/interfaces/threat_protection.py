"""Threat protection service port.

The capability the URL analysis use case depends on to consult and update the
blacklist. Owned by Core so ``UrlAnalysisService`` depends on this abstraction
rather than importing another service (Dependency Inversion). The concrete
``ThreatIntelligenceService`` implements it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.constants import ArtifactType, BlockSource
from core.domain.analysis import UrlAnalysis
from core.domain.intelligence import IntelligenceReport
from core.domain.url import Url
from core.entities.threat_entry import ThreatEntry


class IThreatProtectionService(ABC):
    """Consults and maintains the threat blacklist."""

    @abstractmethod
    def lookup(self, url: Url) -> ThreatEntry | None:
        """Return the blacklist entry for ``url``, or ``None`` if not listed."""

    @abstractmethod
    def record_detection(
        self, url: Url, analysis: UrlAnalysis, *, source: BlockSource = BlockSource.AI
    ) -> ThreatEntry:
        """Add or update the blacklist entry for a malicious URL detection."""

    @abstractmethod
    def record_report(
        self,
        artifact_hash: str,
        artifact: str,
        report: IntelligenceReport,
        *,
        artifact_type: ArtifactType,
        source: BlockSource = BlockSource.AI,
    ) -> ThreatEntry:
        """Add or update the blacklist entry for any malicious detection."""

    @abstractmethod
    def register_hit(self, entry: ThreatEntry) -> ThreatEntry:
        """Record a repeat detection of an already-blacklisted artifact."""

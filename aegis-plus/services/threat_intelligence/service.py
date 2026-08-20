"""Threat intelligence service.

Maintains the blacklist and enforces application-level auto-protection. It
implements the Core ``IThreatProtectionService`` port (consumed by the URL
analysis use case) and adds listing, statistics, and open-guarding used by the
delivery layer. It depends only on Core ports; persistence goes through the Unit
of Work, and every state change is audited.

Designed as a reusable foundation: the entry is artifact-agnostic, so email,
file, and network detections can register threats through the same service.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from core.constants import ArtifactType, AuditOutcome, BlockSource
from core.domain.analysis import UrlAnalysis
from core.domain.intelligence import IntelligenceReport
from core.domain.url import Url
from core.entities import ThreatEntry
from core.interfaces import (
    IAuditTrail,
    ILogger,
    IThreatIntelligenceRepository,
    IThreatProtectionService,
    IUnitOfWork,
)

_HIGH_RISK_THRESHOLD = 0.70


@dataclass(frozen=True, slots=True)
class ThreatStats:
    """Aggregate blacklist statistics for the dashboard."""

    total_blacklisted: int
    threats_blocked: int
    high_risk_count: int
    most_recent: str | None


class ThreatIntelligenceService(IThreatProtectionService):
    """Blacklist maintenance and auto-protection."""

    def __init__(
        self,
        unit_of_work_factory: Callable[[], IUnitOfWork],
        audit: IAuditTrail,
        logger: ILogger,
    ) -> None:
        """Initialize the service.

        Args:
            unit_of_work_factory: Produces a Unit of Work for persistence.
            audit: The audit trail port.
            logger: Injected logger.
        """
        self._unit_of_work_factory = unit_of_work_factory
        self._audit = audit
        self._logger = logger

    @staticmethod
    def _repo(uow: IUnitOfWork) -> IThreatIntelligenceRepository:
        return cast(IThreatIntelligenceRepository, uow.get_repository(ThreatEntry))

    # --- IThreatProtectionService ---------------------------------------

    def lookup(self, url: Url) -> ThreatEntry | None:
        """Return the blacklist entry for ``url``, or ``None`` if not listed."""
        with self._unit_of_work_factory() as uow:
            return self._repo(uow).find_by_hash(url.fingerprint)

    def record_detection(
        self, url: Url, analysis: UrlAnalysis, *, source: BlockSource = BlockSource.AI
    ) -> ThreatEntry:
        """Add or update the blacklist entry for a malicious URL detection."""
        return self._upsert(
            ThreatEntry.from_analysis(url, analysis, source=source), resource=str(url)
        )

    def record_report(
        self,
        artifact_hash: str,
        artifact: str,
        report: IntelligenceReport,
        *,
        artifact_type: ArtifactType,
        source: BlockSource = BlockSource.AI,
    ) -> ThreatEntry:
        """Add or update the blacklist entry for any malicious detection.

        The generic recording path shared by every detection vertical (URL,
        email, and future artifact types).
        """
        return self._upsert(
            ThreatEntry.from_report(
                artifact_hash,
                artifact,
                report,
                artifact_type=artifact_type,
                source=source,
            ),
            resource=artifact,
        )

    def _upsert(self, candidate: ThreatEntry, *, resource: str) -> ThreatEntry:
        """Insert a new blacklist entry or record a repeat on an existing one."""
        with self._unit_of_work_factory() as uow:
            repo = self._repo(uow)
            existing = repo.find_by_hash(candidate.artifact_hash)
            if existing is not None:
                existing.register_detection()
                entry = repo.update(existing)
            else:
                entry = repo.add(candidate)
            uow.commit()

        self._logger.info(
            "Blacklisted {} [{}] ({})",
            resource,
            entry.artifact_type.value,
            entry.verdict.value,
        )
        self._audit.record(
            "threat.blacklisted",
            outcome=AuditOutcome.SUCCESS,
            resource=resource,
            artifact_type=entry.artifact_type.value,
            verdict=entry.verdict.value,
            risk_score=entry.risk_score,
            block_source=entry.block_source.value,
        )
        return entry

    def register_hit(self, entry: ThreatEntry) -> ThreatEntry:
        """Record a repeat detection of an already-blacklisted artifact."""
        with self._unit_of_work_factory() as uow:
            repo = self._repo(uow)
            current = repo.find_by_hash(entry.artifact_hash)
            if current is None:
                return entry
            current.register_detection()
            updated = repo.update(current)
            uow.commit()

        self._audit.record(
            "threat.blacklist_hit",
            outcome=AuditOutcome.SUCCESS,
            resource=updated.artifact,
            detection_count=updated.detection_count,
        )
        return updated

    # --- Delivery-facing operations -------------------------------------

    def is_blocked(self, url: Url) -> bool:
        """Whether ``url`` is currently blacklisted and blocked."""
        entry = self.lookup(url)
        return entry is not None and entry.blocked

    def guard_open(self, url: Url) -> ThreatEntry | None:
        """Return the blocking entry if opening ``url`` must be prevented.

        Records a ``threat.open_blocked`` audit event when a launch is blocked.
        """
        entry = self.lookup(url)
        if entry is not None and entry.blocked:
            self._audit.record(
                "threat.open_blocked",
                outcome=AuditOutcome.DENIED,
                resource=entry.artifact,
                verdict=entry.verdict.value,
            )
            return entry
        return None

    def get_by_hash(self, artifact_hash: str) -> ThreatEntry | None:
        """Return an entry by hash, auditing the view."""
        with self._unit_of_work_factory() as uow:
            entry = self._repo(uow).find_by_hash(artifact_hash)
        if entry is not None:
            self._audit.record(
                "threat.viewed",
                outcome=AuditOutcome.SUCCESS,
                resource=entry.artifact,
            )
        return entry

    def list_threats(self) -> list[ThreatEntry]:
        """Return all blacklist entries, most recently detected first."""
        with self._unit_of_work_factory() as uow:
            return self._repo(uow).list_recent()

    def stats(self) -> ThreatStats:
        """Compute aggregate blacklist statistics."""
        entries = self.list_threats()
        return ThreatStats(
            total_blacklisted=len(entries),
            threats_blocked=sum(e.detection_count for e in entries),
            high_risk_count=sum(1 for e in entries if e.risk_score >= _HIGH_RISK_THRESHOLD),
            most_recent=entries[0].artifact if entries else None,
        )

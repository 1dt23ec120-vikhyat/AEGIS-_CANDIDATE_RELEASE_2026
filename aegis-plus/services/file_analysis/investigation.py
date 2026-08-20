"""File investigation service.

Persists and retrieves analyst workflow metadata (status, priority, tags, notes)
for an analyzed file, keyed by the file scan identifier. Kept separate from the
detection pipeline so analyst annotations never alter detection evidence.
"""

from __future__ import annotations

from collections.abc import Callable

from core.constants import InvestigationPriority, InvestigationStatus
from core.entities import FileInvestigation
from core.interfaces import IAuditTrail, ILogger, IUnitOfWork
from services.pipeline import IntelligencePublisher

_ACTION = "file.investigation.save"


class FileInvestigationService:
    """Application service for analyst investigation metadata."""

    def __init__(
        self,
        unit_of_work_factory: Callable[[], IUnitOfWork],
        audit: IAuditTrail,
        logger: ILogger,
        publisher: IntelligencePublisher | None = None,
    ) -> None:
        """Initialize the service.

        Args:
            unit_of_work_factory: Produces a Unit of Work for persistence.
            audit: The audit trail port.
            logger: Injected logger.
            publisher: Optional live-pipeline publisher; when provided, saved
                investigations are published as intelligence events.
        """
        self._unit_of_work_factory = unit_of_work_factory
        self._audit = audit
        self._logger = logger
        self._publisher = publisher

    def get(self, scan_id: str) -> FileInvestigation | None:
        """Return the investigation for ``scan_id``, or ``None`` if absent."""
        with self._unit_of_work_factory() as uow:
            for investigation in uow.get_repository(FileInvestigation).list():
                if investigation.scan_id == scan_id:
                    return investigation
        return None

    def save(
        self,
        scan_id: str,
        *,
        status: InvestigationStatus,
        priority: InvestigationPriority,
        tags: tuple[str, ...],
        notes: str,
    ) -> FileInvestigation:
        """Create or update the investigation for ``scan_id``."""
        with self._unit_of_work_factory() as uow:
            repo = uow.get_repository(FileInvestigation)
            existing = next((i for i in repo.list() if i.scan_id == scan_id), None)
            if existing is not None:
                existing.update(status=status, priority=priority, tags=tags, notes=notes)
                investigation = repo.update(existing)
            else:
                investigation = repo.add(
                    FileInvestigation(
                        scan_id=scan_id,
                        status=status,
                        priority=priority,
                        tags=tags,
                        notes=notes,
                    )
                )
            uow.commit()

        self._logger.info(
            "Investigation saved for {}: {} / {}",
            scan_id,
            investigation.status.value,
            investigation.priority.value,
        )
        self._audit.success(
            _ACTION,
            resource=scan_id,
            status=investigation.status.value,
            priority=investigation.priority.value,
        )
        if self._publisher is not None:
            self._publisher.investigation_recorded(
                source="file-investigation",
                investigation_id=str(investigation.id),
                artifact_id=scan_id,
                status=investigation.status.value,
            )
        return investigation

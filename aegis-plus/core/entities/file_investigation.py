"""File investigation aggregate.

Analyst workflow metadata attached to an :class:`FileScan`: an investigation
status, priority, free-form tags, and notes. It is the persisted record backing
the analyst-notes panel of the investigation workspace, kept separate from the
detection result so analyst annotations never mutate detection evidence.
"""

from __future__ import annotations

from datetime import datetime

from core.constants import InvestigationPriority, InvestigationStatus
from core.domain.value_objects import EntityId
from core.entities.base import AggregateRoot


class FileInvestigation(AggregateRoot):
    """Analyst annotations for an analyzed file."""

    def __init__(
        self,
        *,
        scan_id: str,
        status: InvestigationStatus = InvestigationStatus.OPEN,
        priority: InvestigationPriority = InvestigationPriority.MEDIUM,
        tags: tuple[str, ...] = (),
        notes: str = "",
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize an investigation record.

        Args:
            scan_id: The identifier of the associated file scan.
            status: The investigation status.
            priority: The analyst-assigned priority.
            tags: Free-form classification tags.
            notes: Analyst notes.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp.
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        self.scan_id = scan_id
        self.status = status
        self.priority = priority
        self.tags = tags
        self.notes = notes

    def update(
        self,
        *,
        status: InvestigationStatus,
        priority: InvestigationPriority,
        tags: tuple[str, ...],
        notes: str,
    ) -> None:
        """Apply an analyst edit and bump the modified timestamp."""
        self.status = status
        self.priority = priority
        self.tags = tags
        self.notes = notes
        self.touch()

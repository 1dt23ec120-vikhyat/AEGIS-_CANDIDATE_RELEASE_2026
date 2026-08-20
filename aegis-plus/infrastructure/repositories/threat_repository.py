"""Threat intelligence repository.

Extends the generic SQLAlchemy repository with the hash lookup and ordered
listing the protection use case needs, implementing the Core
:class:`IThreatIntelligenceRepository` port. Query details stay here; callers see
only domain operations.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.entities import ThreatEntry
from core.interfaces import IThreatIntelligenceRepository
from infrastructure.database import mappers
from infrastructure.database.models import ThreatEntryRow
from infrastructure.repositories.base_repository import SqlAlchemyRepository


class SqlAlchemyThreatIntelligenceRepository(
    SqlAlchemyRepository[ThreatEntry, ThreatEntryRow],
    IThreatIntelligenceRepository,
):
    """Threat intelligence persistence with hash lookup and ordering."""

    def __init__(self, session: Session) -> None:
        """Initialize the repository bound to a session."""
        super().__init__(
            session,
            row_type=ThreatEntryRow,
            to_entity=mappers.threat_entry_to_entity,
            to_row=mappers.threat_entry_to_row,
            apply_updates=mappers.apply_threat_entry_updates,
        )

    def find_by_hash(self, artifact_hash: str) -> ThreatEntry | None:
        """Return the entry for ``artifact_hash``, or ``None`` if absent."""
        stmt = select(ThreatEntryRow).where(ThreatEntryRow.artifact_hash == artifact_hash)
        row = self._session.execute(stmt).scalar_one_or_none()
        return mappers.threat_entry_to_entity(row) if row is not None else None

    def list_recent(self) -> list[ThreatEntry]:
        """Return all entries, most recently detected first."""
        stmt = select(ThreatEntryRow).order_by(ThreatEntryRow.last_detected.desc())
        rows = self._session.execute(stmt).scalars().all()
        return [mappers.threat_entry_to_entity(row) for row in rows]

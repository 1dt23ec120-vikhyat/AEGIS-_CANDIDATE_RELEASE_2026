"""Persisted configuration entity.

Represents a persisted configuration key/value pair as a domain entity. This is
distinct from the runtime configuration subsystem (the ``config`` package): it
models configuration that is stored in and evolves through the database.
"""

from __future__ import annotations

from datetime import datetime

from core.domain.value_objects import EntityId
from core.entities.base import BaseEntity


class Configuration(BaseEntity):
    """A persisted configuration entry."""

    def __init__(
        self,
        *,
        key: str,
        value: str,
        description: str | None = None,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize a configuration entry.

        Args:
            key: Unique configuration key.
            value: Configuration value.
            description: Optional human-readable description.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp.
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        self.key = key
        self.value = value
        self.description = description

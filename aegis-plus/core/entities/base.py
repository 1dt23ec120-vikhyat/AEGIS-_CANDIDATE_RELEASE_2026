"""Base entity and aggregate root.

Implements domain-driven entities with identity-based equality. Entities are
pure domain objects: they carry business identity, behaviour, and shared audit
timestamps, but no persistence or ORM concerns (entity-design standard). The
mapping between entities and database rows lives in the infrastructure layer.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.domain.value_objects import EntityId


class BaseEntity:
    """Base class for domain entities.

    Two entities are equal when they are of the same concrete type and share the
    same identity, regardless of their other attribute values.
    """

    def __init__(
        self,
        *,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize the entity.

        Args:
            entity_id: The entity identity. A new one is generated if omitted.
            created_at: Creation timestamp (UTC). Defaults to now.
            updated_at: Last-modified timestamp (UTC). Defaults to now.
        """
        now = datetime.now(UTC)
        self._id = entity_id or EntityId.generate()
        self._created_at = created_at or now
        self._updated_at = updated_at or now

    @property
    def id(self) -> EntityId:
        """The entity's identity."""
        return self._id

    @property
    def created_at(self) -> datetime:
        """When the entity was created (UTC)."""
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        """When the entity was last modified (UTC)."""
        return self._updated_at

    def touch(self) -> None:
        """Record that the entity has been modified now."""
        self._updated_at = datetime.now(UTC)

    def __eq__(self, other: object) -> bool:
        """Return equality based on concrete type and identity."""
        if not isinstance(other, BaseEntity):
            return NotImplemented
        return type(self) is type(other) and self._id == other._id

    def __hash__(self) -> int:
        """Hash based on concrete type and identity."""
        return hash((type(self).__name__, self._id))

    def __repr__(self) -> str:
        """Return a concise representation including the identity."""
        return f"{type(self).__name__}(id={self._id})"


class AggregateRoot(BaseEntity):
    """Base class for aggregate roots (DDD consistency boundaries)."""

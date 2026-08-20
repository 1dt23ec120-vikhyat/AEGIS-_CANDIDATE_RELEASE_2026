"""Repository port.

``IRepository`` expresses persistence as a domain capability: storing and
retrieving entities by identity. It is generic over the entity type and returns
domain entities, never persistence rows. Concrete repositories live in
infrastructure and are injected at the composition root.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from core.domain.value_objects import EntityId
from core.entities.base import BaseEntity

TEntity = TypeVar("TEntity", bound=BaseEntity)


class IRepository(ABC, Generic[TEntity]):
    """Persistence contract for a single entity type."""

    @abstractmethod
    def add(self, entity: TEntity) -> TEntity:
        """Persist a new entity and return it."""

    @abstractmethod
    def get(self, entity_id: EntityId) -> TEntity | None:
        """Return the entity with ``entity_id``, or ``None`` if absent."""

    @abstractmethod
    def list(self) -> list[TEntity]:
        """Return all entities."""

    @abstractmethod
    def update(self, entity: TEntity) -> TEntity:
        """Persist changes to an existing entity and return it."""

    @abstractmethod
    def delete(self, entity_id: EntityId) -> None:
        """Remove the entity with ``entity_id``."""

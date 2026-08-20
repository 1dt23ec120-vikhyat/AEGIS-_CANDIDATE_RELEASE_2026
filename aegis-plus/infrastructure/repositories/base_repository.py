"""Generic SQLAlchemy repository.

A single, reusable implementation of the Core :class:`IRepository` port. It is
parameterized with the ORM row type and the mapping callables for an entity, so
one class serves every entity without duplicating persistence logic. It exposes
only domain-oriented operations; SQLAlchemy details do not leak to callers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.domain import EntityId
from core.entities.base import BaseEntity
from core.exceptions import NotFoundError
from core.interfaces import IRepository

TEntity = TypeVar("TEntity", bound=BaseEntity)
TRow = TypeVar("TRow")


class SqlAlchemyRepository(IRepository[TEntity], Generic[TEntity, TRow]):
    """Maps a Core entity to an ORM row type within a shared session."""

    def __init__(
        self,
        session: Session,
        *,
        row_type: type[TRow],
        to_entity: Callable[[TRow], TEntity],
        to_row: Callable[[TEntity], TRow],
        apply_updates: Callable[[TRow, TEntity], None],
    ) -> None:
        """Initialize the repository.

        Args:
            session: The active session (owned by the Unit of Work).
            row_type: The ORM row class for this entity.
            to_entity: Maps a row to a domain entity.
            to_row: Maps a domain entity to a new row.
            apply_updates: Copies entity fields onto an existing row.
        """
        self._session = session
        self._row_type = row_type
        self._to_entity = to_entity
        self._to_row = to_row
        self._apply_updates = apply_updates

    def add(self, entity: TEntity) -> TEntity:
        """Persist a new entity and return it."""
        self._session.add(self._to_row(entity))
        self._session.flush()
        return entity

    def get(self, entity_id: EntityId) -> TEntity | None:
        """Return the entity with ``entity_id``, or ``None`` if absent."""
        row = self._session.get(self._row_type, entity_id.value)
        return self._to_entity(row) if row is not None else None

    def list(self) -> list[TEntity]:
        """Return all entities."""
        rows = self._session.scalars(select(self._row_type)).all()
        return [self._to_entity(row) for row in rows]

    def update(self, entity: TEntity) -> TEntity:
        """Persist changes to an existing entity and return it.

        Raises:
            NotFoundError: If the entity does not exist.
        """
        row = self._session.get(self._row_type, entity.id.value)
        if row is None:
            raise NotFoundError(f"{type(entity).__name__} {entity.id} not found")
        self._apply_updates(row, entity)
        self._session.flush()
        return entity

    def delete(self, entity_id: EntityId) -> None:
        """Remove the entity with ``entity_id`` if it exists."""
        row = self._session.get(self._row_type, entity_id.value)
        if row is not None:
            self._session.delete(row)
            self._session.flush()

"""Unit of Work port.

``IUnitOfWork`` coordinates a transactional boundary. Repositories obtained from
the same unit share its transaction, so multiple repositories can participate in
a single atomic operation. Concrete units live in infrastructure and are used as
context managers::

    with unit_of_work as uow:
        uow.get_repository(AuditLog).add(entry)
        uow.commit()

Changes are discarded unless :meth:`commit` is called explicitly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType
from typing import TypeVar

from core.entities.base import BaseEntity
from core.interfaces.repository import IRepository

TEntity = TypeVar("TEntity", bound=BaseEntity)


class IUnitOfWork(ABC):
    """Transactional boundary coordinating one or more repositories."""

    @abstractmethod
    def __enter__(self) -> IUnitOfWork:
        """Begin the unit of work and return it."""

    @abstractmethod
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """End the unit of work, rolling back if not committed."""

    @abstractmethod
    def commit(self) -> None:
        """Commit the current transaction."""

    @abstractmethod
    def rollback(self) -> None:
        """Roll back the current transaction."""

    @abstractmethod
    def get_repository(self, entity_type: type[TEntity]) -> IRepository[TEntity]:
        """Return the repository for ``entity_type`` bound to this unit.

        Args:
            entity_type: The entity class whose repository is requested.

        Returns:
            A repository participating in this unit's transaction.

        Raises:
            KeyError: If no repository is registered for ``entity_type``.
        """

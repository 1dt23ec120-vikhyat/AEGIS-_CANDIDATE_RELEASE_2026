"""SQLAlchemy Unit of Work.

Implements the Core :class:`IUnitOfWork` port. It owns a single session for the
duration of the unit; every repository obtained via :meth:`get_repository` is
bound to that session, so all participate in one atomic transaction. Changes are
discarded unless :meth:`commit` is called explicitly.
"""

from __future__ import annotations

from types import TracebackType
from typing import TypeVar, cast

from sqlalchemy.orm import Session, sessionmaker

from core.entities.base import BaseEntity
from core.interfaces import IRepository, IUnitOfWork
from infrastructure.repositories.registry import (
    RepositoryFactory,
    default_repository_factories,
)

TEntity = TypeVar("TEntity", bound=BaseEntity)


class SqlAlchemyUnitOfWork(IUnitOfWork):
    """A Unit of Work backed by a SQLAlchemy session."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        repository_factories: dict[type[BaseEntity], RepositoryFactory] | None = None,
    ) -> None:
        """Initialize the unit of work.

        Args:
            session_factory: Produces a new session when the unit is entered.
            repository_factories: Entity-type to repository-factory registry.
                Defaults to the standard registry.
        """
        self._session_factory = session_factory
        self._repository_factories = (
            repository_factories
            if repository_factories is not None
            else default_repository_factories()
        )
        self._session: Session | None = None
        self._repositories: dict[type[BaseEntity], IRepository[BaseEntity]] = {}
        self._committed = False

    def __enter__(self) -> IUnitOfWork:
        """Open a session and begin the unit."""
        self._session = self._session_factory()
        self._repositories = {}
        self._committed = False
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Roll back if not committed (or on error), then close the session."""
        session = self._require_session()
        try:
            if exc_type is not None or not self._committed:
                session.rollback()
        finally:
            session.close()
            self._session = None
            self._repositories = {}

    def commit(self) -> None:
        """Commit the current transaction."""
        self._require_session().commit()
        self._committed = True

    def rollback(self) -> None:
        """Roll back the current transaction."""
        self._require_session().rollback()

    def get_repository(self, entity_type: type[TEntity]) -> IRepository[TEntity]:
        """Return the repository for ``entity_type`` bound to this unit.

        Raises:
            KeyError: If no repository is registered for ``entity_type``.
        """
        session = self._require_session()
        if entity_type not in self._repositories:
            try:
                factory = self._repository_factories[entity_type]
            except KeyError as exc:
                raise KeyError(f"No repository registered for {entity_type.__name__}") from exc
            self._repositories[entity_type] = factory(session)
        return cast(IRepository[TEntity], self._repositories[entity_type])

    def _require_session(self) -> Session:
        """Return the active session or raise if used outside its context."""
        if self._session is None:
            raise RuntimeError("Unit of work must be used within a 'with' block")
        return self._session

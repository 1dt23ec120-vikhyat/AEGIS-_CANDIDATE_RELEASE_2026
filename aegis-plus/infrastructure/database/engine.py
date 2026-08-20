"""Database engine and session management.

Encapsulates engine creation, connection management, and session construction.
Vendor-specific behaviour (SQLite pragmas and connect args, connection pooling)
is confined here so the rest of the system remains database-agnostic. Schema
creation via :meth:`Database.create_all` is intended only for controlled
development and test scenarios; Alembic migrations are authoritative for schema
evolution.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from infrastructure.database.base import Base


class Database:
    """Owns the SQLAlchemy engine and session factory for one database."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        """Create the engine and session factory.

        Args:
            url: SQLAlchemy database URL (SQLite or PostgreSQL).
            echo: Whether to echo emitted SQL (diagnostic use).
        """
        self._engine = self._build_engine(url, echo=echo)
        self._session_factory: sessionmaker[Session] = sessionmaker(
            bind=self._engine, expire_on_commit=False
        )

    @property
    def engine(self) -> Engine:
        """The underlying SQLAlchemy engine."""
        return self._engine

    @property
    def session_factory(self) -> sessionmaker[Session]:
        """A factory producing sessions bound to this engine."""
        return self._session_factory

    @staticmethod
    def _build_engine(url: str, *, echo: bool) -> Engine:
        """Build an engine, applying backend-specific settings."""
        connect_args: dict[str, Any] = {}
        is_sqlite = url.startswith("sqlite")
        if is_sqlite:
            # Allow use across threads (desktop UI + embedded backend).
            connect_args["check_same_thread"] = False

        engine = create_engine(
            url,
            echo=echo,
            future=True,
            pool_pre_ping=True,
            connect_args=connect_args,
        )

        if is_sqlite:
            # Enforce foreign-key constraints on SQLite (off by default).
            @event.listens_for(engine, "connect")
            def _enable_sqlite_fk(dbapi_connection: Any, _record: Any) -> None:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        return engine

    def create_all(self) -> None:
        """Create all tables directly from metadata.

        Controlled development and test use only. Production schema evolution is
        performed exclusively through Alembic migrations.
        """
        Base.metadata.create_all(self._engine)

    def dispose(self) -> None:
        """Dispose the engine and release pooled connections."""
        self._engine.dispose()

    def ping(self) -> None:
        """Verify connectivity by opening a connection and running a query.

        Raises:
            Exception: Any error indicates the database is unreachable. Callers
                (e.g. health checks) translate this into a status.
        """
        with self._engine.connect() as connection:
            connection.execute(text("SELECT 1"))

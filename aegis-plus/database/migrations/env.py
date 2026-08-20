"""Alembic migration environment.

Resolves the database URL from the application configuration and targets the
ORM metadata. Batch mode is enabled so ALTER operations work on SQLite, keeping
migrations portable across SQLite and PostgreSQL.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

# Import the config subsystem and ORM metadata. Importing the models module
# registers every table on the shared metadata.
from config import get_settings
from infrastructure.database import models  # noqa: F401  (registers tables)
from infrastructure.database.base import Base

target_metadata = Base.metadata


def _database_url() -> str:
    """Return the database URL, preferring an explicitly configured one.

    The migrator sets ``sqlalchemy.url`` on the Alembic config so it can target a
    specific database (e.g. a test database); otherwise the application
    configuration is used.
    """
    configured = context.config.get_main_option("sqlalchemy.url")
    return configured or get_settings().database.url


def run_migrations_offline() -> None:
    """Run migrations in offline (SQL-emitting) mode."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = create_engine(_database_url(), poolclass=pool.NullPool, future=True)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

"""Migration runner.

Applies Alembic migrations programmatically, so startup can bring the schema to
the latest revision (``upgrade head``). Alembic remains the sole authoritative
schema mechanism; this is only the invocation path used at application launch and
in tests. The migration scripts are a fixed source resource, located relative to
this package rather than the user's data directory.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from core.exceptions import PersistenceError

_MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "database" / "migrations"


def _build_config(database_url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def apply_migrations(database_url: str) -> None:
    """Upgrade the database at ``database_url`` to the latest revision.

    Args:
        database_url: The target database URL.

    Raises:
        InfrastructureError: If the migration run fails.
    """
    try:
        command.upgrade(_build_config(database_url), "head")
    except Exception as exc:  # broad: any migration failure maps to a domain error
        raise PersistenceError(f"Database migration failed: {exc}") from exc

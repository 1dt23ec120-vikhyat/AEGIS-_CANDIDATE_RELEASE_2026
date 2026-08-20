"""SQLAlchemy declarative base.

Defines the declarative base and shared metadata for all ORM row models. ORM
models are an infrastructure concern and are never referenced by the Core domain.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Explicit, database-neutral naming convention so constraint and index names are
# deterministic across backends (important for Alembic autogenerate on SQLite).
_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all AEGIS+ ORM row models."""

    metadata = MetaData(naming_convention=_NAMING_CONVENTION)

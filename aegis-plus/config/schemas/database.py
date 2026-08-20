"""Database configuration schema.

Database-agnostic by design: the URL selects the backend (SQLite for v1.0,
PostgreSQL-ready). Credentials, when required by a non-SQLite backend, must be
supplied through the URL via environment variables rather than committed files.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from config import defaults


class DatabaseSettings(BaseModel):
    """Persistence configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(default=defaults.DEFAULT_DATABASE_URL, min_length=1)
    echo: bool = Field(default=defaults.DEFAULT_DATABASE_ECHO)

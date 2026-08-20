"""Application and embedded-backend configuration schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from config import defaults
from config.environments import Environment


class BackendSettings(BaseModel):
    """Embedded local backend (FastAPI) network configuration.

    The backend binds to loopback by default (decision #1) and is never exposed
    off-host without an explicit configuration change.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = Field(default=defaults.DEFAULT_BACKEND_HOST, min_length=1)
    port: int = Field(
        default=defaults.DEFAULT_BACKEND_PORT,
        ge=defaults.MIN_TCP_PORT,
        le=defaults.MAX_TCP_PORT,
    )


class ApplicationSettings(BaseModel):
    """Top-level application configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(default=defaults.DEFAULT_APP_NAME, min_length=1)
    version: str = Field(default=defaults.DEFAULT_APP_VERSION, min_length=1)
    environment: Environment = Field(default=Environment(defaults.DEFAULT_ENVIRONMENT))
    debug: bool = Field(default=defaults.DEFAULT_DEBUG)

    @field_validator("environment", mode="before")
    @classmethod
    def _coerce_environment(cls, value: Any) -> Environment:
        """Parse the environment case-insensitively with a friendly error."""
        if isinstance(value, Environment):
            return value
        return Environment.from_string(str(value))

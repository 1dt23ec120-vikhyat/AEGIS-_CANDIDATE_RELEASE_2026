"""Logging configuration schema.

Describes the logging *policy* (level, destination, rotation, retention). The
logging *runtime* (Loguru configuration) is implemented separately in
``infrastructure/logging`` and consumes this schema.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from config import defaults


class LoggingSettings(BaseModel):
    """Logging policy configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    level: str = Field(default=defaults.DEFAULT_LOG_LEVEL)
    directory: str = Field(default=defaults.DEFAULT_LOG_DIR, min_length=1)
    rotation: str = Field(default=defaults.DEFAULT_LOG_ROTATION, min_length=1)
    retention_days: int = Field(default=defaults.DEFAULT_LOG_RETENTION_DAYS, ge=1)

    @field_validator("level", mode="before")
    @classmethod
    def _normalize_level(cls, value: str) -> str:
        """Uppercase and validate the log level against supported values."""
        normalized = str(value).strip().upper()
        if normalized not in defaults.VALID_LOG_LEVELS:
            valid = ", ".join(defaults.VALID_LOG_LEVELS)
            raise ValueError(f"Invalid log level '{value}'. Valid levels: {valid}.")
        return normalized

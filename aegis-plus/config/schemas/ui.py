"""User interface configuration schema."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from config import defaults


class UISettings(BaseModel):
    """Presentation-layer configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    theme: str = Field(default=defaults.DEFAULT_THEME)
    language: str = Field(default=defaults.DEFAULT_LANGUAGE, min_length=2)

    @field_validator("theme", mode="before")
    @classmethod
    def _validate_theme(cls, value: str) -> str:
        """Validate the theme against supported themes."""
        normalized = str(value).strip().lower()
        if normalized not in defaults.VALID_THEMES:
            valid = ", ".join(defaults.VALID_THEMES)
            raise ValueError(f"Invalid theme '{value}'. Valid themes: {valid}.")
        return normalized

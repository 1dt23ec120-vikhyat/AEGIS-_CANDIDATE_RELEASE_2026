"""Root settings aggregate and access API.

Composes the individual configuration sections into a single immutable
``Settings`` object, orchestrates loading (YAML + environment) and validation,
and exposes a cached accessor so configuration is read from disk only once
(supporting the startup-time budget in NFR §3).
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from config.exceptions import ConfigurationValidationError
from config.loader import build_config_mapping, load_env_file
from config.paths import ProjectPaths
from config.schemas import (
    AISettings,
    ApplicationSettings,
    BackendSettings,
    CopilotSettings,
    DatabaseSettings,
    GmailSettings,
    LoggingSettings,
    SecuritySettings,
    UISettings,
)
from config.validation import validate_settings


class Settings(BaseModel):
    """Immutable aggregate of all configuration sections."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    application: ApplicationSettings = Field(default_factory=ApplicationSettings)
    backend: BackendSettings = Field(default_factory=BackendSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    ui: UISettings = Field(default_factory=UISettings)
    ai: AISettings = Field(default_factory=AISettings)
    copilot: CopilotSettings = Field(default_factory=CopilotSettings)
    gmail: GmailSettings = Field(default_factory=GmailSettings)


def load_settings(
    paths: ProjectPaths | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    use_env_file: bool = True,
) -> Settings:
    """Load, construct, and validate the settings aggregate.

    Args:
        paths: Resolved project paths. Defaults to the repository layout.
        environ: Explicit environment mapping. Defaults to ``os.environ``.
            Supplying this (typically with ``use_env_file=False``) gives tests
            full control over the environment.
        use_env_file: Whether to load a local ``.env`` file into the
            environment before reading variables.

    Returns:
        A validated :class:`Settings` instance.

    Raises:
        ConfigurationValidationError: If schema or cross-field validation fails.
        ConfigurationFileError: If a configuration file is malformed.
    """
    resolved_paths = paths or ProjectPaths.create()

    if use_env_file:
        load_env_file(resolved_paths)

    mapping: dict[str, Any] = build_config_mapping(resolved_paths, environ)

    try:
        settings = Settings(**mapping)
    except ValidationError as exc:
        raise ConfigurationValidationError(
            f"Configuration failed schema validation: {exc}"
        ) from exc

    validate_settings(settings)
    return settings


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, loading them once and caching.

    Returns:
        The cached :class:`Settings` instance.
    """
    return load_settings()


def reset_settings_cache() -> None:
    """Clear the cached settings.

    Intended for tests and for controlled configuration reloads.
    """
    get_settings.cache_clear()

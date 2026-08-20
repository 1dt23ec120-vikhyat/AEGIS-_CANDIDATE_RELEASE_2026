"""AEGIS+ configuration subsystem.

A self-contained, foundational package that loads, validates, and exposes
application configuration. It depends on no other internal package so that every
architectural layer may read configuration without introducing dependency
cycles.

Typical usage::

    from config import get_settings

    settings = get_settings()
    port = settings.backend.port

Loading precedence (lowest to highest): schema defaults, YAML files, then
environment variables. Secrets are read only from the environment.
"""

from config.environments import Environment
from config.exceptions import (
    ConfigurationError,
    ConfigurationFileError,
    ConfigurationValidationError,
)
from config.paths import ProjectPaths
from config.settings import (
    Settings,
    get_settings,
    load_settings,
    reset_settings_cache,
)

__all__ = [
    "ConfigurationError",
    "ConfigurationFileError",
    "ConfigurationValidationError",
    "Environment",
    "ProjectPaths",
    "Settings",
    "get_settings",
    "load_settings",
    "reset_settings_cache",
]

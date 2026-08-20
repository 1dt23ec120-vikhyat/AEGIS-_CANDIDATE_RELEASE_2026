"""Configuration provider adapter.

Implements the Core :class:`IConfigurationProvider` port over the framework-based
configuration package. This is the boundary where the configuration package's
leaf exceptions are mapped 1:1 into the centralized Core exception hierarchy, so
callers only ever see Core errors.
"""

from __future__ import annotations

from config import ConfigurationError as _LeafConfigurationError
from config import ConfigurationFileError as _LeafConfigurationFileError
from config import ConfigurationValidationError as _LeafConfigurationValidationError
from config import Settings, get_settings
from core.exceptions import (
    ConfigurationError,
    ConfigurationFileError,
    ConfigurationValidationError,
)
from core.interfaces import IConfigurationProvider

# Maps configuration leaf exception types to their Core counterparts. Ordered
# most-specific first so subclass checks resolve correctly.
_ERROR_MAP: tuple[tuple[type[_LeafConfigurationError], type[ConfigurationError]], ...] = (
    (_LeafConfigurationFileError, ConfigurationFileError),
    (_LeafConfigurationValidationError, ConfigurationValidationError),
)


def _to_core_error(exc: _LeafConfigurationError) -> ConfigurationError:
    """Map a configuration leaf error to its Core equivalent."""
    for leaf_type, core_type in _ERROR_MAP:
        if isinstance(exc, leaf_type):
            return core_type(str(exc))
    return ConfigurationError(str(exc))


class ConfigurationProvider(IConfigurationProvider):
    """Adapts loaded configuration to the Core configuration port."""

    def __init__(self, settings: Settings) -> None:
        """Initialize the provider with already-loaded settings.

        Args:
            settings: The validated configuration aggregate.
        """
        self._settings = settings

    @classmethod
    def load(cls) -> ConfigurationProvider:
        """Load configuration and wrap it in a provider.

        Returns:
            A provider over freshly loaded settings.

        Raises:
            ConfigurationError: If loading or validation fails. Leaf errors are
                mapped into the Core hierarchy.
        """
        try:
            settings = get_settings()
        except _LeafConfigurationError as exc:
            raise _to_core_error(exc) from exc
        return cls(settings)

    def environment(self) -> str:
        """Return the active environment name."""
        return self._settings.application.environment.value

    def is_debug(self) -> bool:
        """Return whether debug mode is enabled."""
        return self._settings.application.debug

    def database_url(self) -> str:
        """Return the configured database URL."""
        return self._settings.database.url

    def database_echo(self) -> bool:
        """Return whether the database should echo SQL."""
        return self._settings.database.echo

    def log_level(self) -> str:
        """Return the configured logging level."""
        return self._settings.logging.level

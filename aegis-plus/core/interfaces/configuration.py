"""Configuration provider port.

``IConfigurationProvider`` gives the domain read access to configuration without
depending on the configuration framework. It returns framework-free primitives;
the infrastructure adapter maps the concrete (Pydantic-based) configuration onto
this contract. The surface grows additively as new domain needs arise, keeping
the contract stable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class IConfigurationProvider(ABC):
    """Read-only access to configuration in framework-neutral terms."""

    @abstractmethod
    def environment(self) -> str:
        """Return the active environment name."""

    @abstractmethod
    def is_debug(self) -> bool:
        """Return whether debug mode is enabled."""

    @abstractmethod
    def database_url(self) -> str:
        """Return the configured database URL."""

    @abstractmethod
    def database_echo(self) -> bool:
        """Return whether the database should echo SQL."""

    @abstractmethod
    def log_level(self) -> str:
        """Return the configured logging level."""

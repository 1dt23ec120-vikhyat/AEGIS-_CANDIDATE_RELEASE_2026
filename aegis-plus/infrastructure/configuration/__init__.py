"""Configuration infrastructure.

Adapts the framework-based configuration package to the Core
:class:`~core.interfaces.IConfigurationProvider` contract and maps configuration
leaf errors into the centralized Core exception hierarchy.
"""

from infrastructure.configuration.provider import ConfigurationProvider

__all__ = ["ConfigurationProvider"]

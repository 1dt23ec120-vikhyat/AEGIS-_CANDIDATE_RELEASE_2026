"""Infrastructure and configuration exceptions.

These represent failures in technical concerns (persistence, configuration,
external integrations). The configuration exceptions mirror the configuration
package's leaf hierarchy so that leaf errors can be mapped 1:1 into the
centralized model at the infrastructure boundary (error-handling standard).
"""

from __future__ import annotations

from core.exceptions.base import AegisError


class InfrastructureError(AegisError):
    """Base class for infrastructure-layer failures."""


class PersistenceError(InfrastructureError):
    """Raised when a persistence operation fails."""


class IntegrationError(InfrastructureError):
    """Raised when an external integration fails."""


class ConfigurationError(InfrastructureError):
    """Base class for configuration errors (maps the config leaf base)."""


class ConfigurationFileError(ConfigurationError):
    """Raised when a configuration file cannot be read or parsed."""


class ConfigurationValidationError(ConfigurationError):
    """Raised when configuration values fail validation."""

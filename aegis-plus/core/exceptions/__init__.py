"""Centralized AEGIS+ exception hierarchy.

All application exceptions derive from :class:`AegisError`. Other layers derive
from or map into this hierarchy rather than defining independent exception
systems (project error-handling standard).
"""

from core.exceptions.ai import AIError, InferenceError, ModelError
from core.exceptions.base import AegisError
from core.exceptions.domain import (
    BusinessRuleError,
    ConflictError,
    DomainError,
    NotFoundError,
    ValidationError,
)
from core.exceptions.infrastructure import (
    ConfigurationError,
    ConfigurationFileError,
    ConfigurationValidationError,
    InfrastructureError,
    IntegrationError,
    PersistenceError,
)
from core.exceptions.security import (
    AuthenticationError,
    AuthorizationError,
    SecurityError,
)

__all__ = [
    "AIError",
    "AegisError",
    "AuthenticationError",
    "AuthorizationError",
    "BusinessRuleError",
    "ConfigurationError",
    "ConfigurationFileError",
    "ConfigurationValidationError",
    "ConflictError",
    "DomainError",
    "InferenceError",
    "InfrastructureError",
    "IntegrationError",
    "ModelError",
    "NotFoundError",
    "PersistenceError",
    "SecurityError",
    "ValidationError",
]

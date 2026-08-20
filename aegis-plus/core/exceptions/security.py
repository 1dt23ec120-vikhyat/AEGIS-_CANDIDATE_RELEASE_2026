"""Security-related exceptions."""

from __future__ import annotations

from core.exceptions.base import AegisError


class SecurityError(AegisError):
    """Base class for security policy violations."""


class AuthenticationError(SecurityError):
    """Raised when authentication fails or is required but absent."""


class AuthorizationError(SecurityError):
    """Raised when an authenticated actor lacks permission for an action."""

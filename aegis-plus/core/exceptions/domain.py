"""Domain-layer exceptions.

Represent violations of business rules and domain invariants. These are raised
by the core layer and surfaced to callers as domain-meaningful failures.
"""

from __future__ import annotations

from core.exceptions.base import AegisError


class DomainError(AegisError):
    """Base class for domain and business-rule errors."""


class ValidationError(DomainError):
    """Raised when input or a value object fails validation."""


class BusinessRuleError(DomainError):
    """Raised when an operation would violate a business rule or invariant."""


class NotFoundError(DomainError):
    """Raised when a requested entity or resource does not exist."""


class ConflictError(DomainError):
    """Raised when an operation conflicts with existing state (e.g. duplicate)."""

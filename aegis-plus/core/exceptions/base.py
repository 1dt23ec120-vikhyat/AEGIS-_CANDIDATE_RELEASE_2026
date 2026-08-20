"""Root exception for AEGIS+.

Every AEGIS+ exception derives from :class:`AegisError`, giving the application a
single, centralized error hierarchy (project error-handling standard). The class
is pure Python and carries an optional structured ``context`` for diagnostics -
which must never contain secrets.
"""

from __future__ import annotations

from typing import Any


class AegisError(Exception):
    """Base class for all AEGIS+ errors."""

    def __init__(self, message: str, *, context: dict[str, Any] | None = None) -> None:
        """Initialize the error.

        Args:
            message: Human-readable description of the error.
            context: Optional structured diagnostic context. Must not contain
                secrets or sensitive data.
        """
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context or {}

    def __str__(self) -> str:
        """Return the human-readable message."""
        return self.message

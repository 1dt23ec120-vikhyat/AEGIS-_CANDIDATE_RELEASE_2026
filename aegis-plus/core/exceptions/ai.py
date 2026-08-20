"""AI subsystem exceptions."""

from __future__ import annotations

from core.exceptions.base import AegisError


class AIError(AegisError):
    """Base class for AI subsystem failures."""


class ModelError(AIError):
    """Raised when a model cannot be loaded, verified, or is unavailable."""


class InferenceError(AIError):
    """Raised when an inference operation fails."""

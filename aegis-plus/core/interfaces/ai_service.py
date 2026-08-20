"""AI service port.

``IAIService`` is the Core-owned base contract for AI-backed services. It
captures the stable capabilities every AI service exposes (identity and
readiness). Analysis operations are intentionally not defined here yet: their
input and output types depend on AI domain models introduced in the AI
milestones, and committing to those signatures now would make the contract
unstable. Those methods will be added additively when the AI domain types exist.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class IAIService(ABC):
    """Base contract for AI-backed services."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the service's stable identifier."""

    @abstractmethod
    def is_ready(self) -> bool:
        """Return whether the service is initialized and ready to serve."""

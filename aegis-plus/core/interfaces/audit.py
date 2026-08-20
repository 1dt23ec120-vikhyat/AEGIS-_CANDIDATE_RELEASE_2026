"""Audit trail port.

The capability services use to record security-relevant actions. Owned by Core
so services audit through an abstraction rather than importing the logging
infrastructure. The infrastructure ``AuditLogger`` implements this port.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from core.constants import AuditOutcome


class IAuditTrail(ABC):
    """Records audit events."""

    @abstractmethod
    def record(
        self,
        action: str,
        *,
        outcome: AuditOutcome,
        actor: str | None = None,
        resource: str | None = None,
        **context: Any,
    ) -> None:
        """Record an audit event with an explicit outcome."""

    @abstractmethod
    def success(self, action: str, **context: Any) -> None:
        """Record a successful action."""

    @abstractmethod
    def failure(self, action: str, **context: Any) -> None:
        """Record a failed action."""

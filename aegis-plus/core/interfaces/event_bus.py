"""Event bus port.

The Core-owned contract for the application event dispatcher. Services publish
events through this interface; the infrastructure layer provides the in-process
implementation. A future async or external-broker implementation would satisfy
the same interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from core.domain.events import EventType, IntelligenceEvent

EventHandler = Callable[[IntelligenceEvent], None]


class IEventBus(ABC):
    """Application event dispatcher contract."""

    @abstractmethod
    def publish(self, event: IntelligenceEvent) -> None:
        """Publish an event to all registered handlers for its type."""

    @abstractmethod
    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Register a handler for events of the given type."""

    @abstractmethod
    def subscriber_count(self, event_type: EventType | None = None) -> int:
        """Return the number of handlers registered for a type (or all types)."""

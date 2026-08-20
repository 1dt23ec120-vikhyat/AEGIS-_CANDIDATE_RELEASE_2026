"""Event history.

An in-memory ring buffer of recent intelligence events for diagnostics. The
history subscribes to the bus and retains the most recent ``max_size`` events,
exposing counts, type statistics, and the event list for the SOC dashboard and
future monitoring.

Events are not persisted in this phase — the history is ephemeral and resets on
application restart.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from core.domain.events import EventType, IntelligenceEvent
from core.interfaces.event_bus import IEventBus

_DEFAULT_MAX = 1000


@dataclass
class EventHistory:
    """In-memory ring buffer of recent intelligence events."""

    max_size: int = _DEFAULT_MAX
    _events: deque[IntelligenceEvent] = field(default_factory=lambda: deque(maxlen=_DEFAULT_MAX))
    _type_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def __post_init__(self) -> None:
        """Ensure the deque has the correct maxlen."""
        self._events = deque(maxlen=self.max_size)

    def record(self, event: IntelligenceEvent) -> None:
        """Record an event into the history."""
        self._events.append(event)
        self._type_counts[event.event_type.value] += 1

    def attach(self, bus: IEventBus) -> None:
        """Subscribe to every event type on the bus."""
        for event_type in EventType:
            bus.subscribe(event_type, self.record)

    @property
    def recent(self) -> tuple[IntelligenceEvent, ...]:
        """The most recent events, newest first."""
        return tuple(reversed(self._events))

    @property
    def count(self) -> int:
        """Total number of events recorded (including evicted ones)."""
        return sum(self._type_counts.values())

    @property
    def type_statistics(self) -> dict[str, int]:
        """Event count per type (lifetime, not just the ring buffer)."""
        return dict(self._type_counts)

    def recent_by_type(self, event_type: EventType) -> tuple[IntelligenceEvent, ...]:
        """Return recent events of a specific type."""
        return tuple(e for e in reversed(self._events) if e.event_type is event_type)

    def summary(self) -> dict[str, object]:
        """Compact summary for diagnostics and SOC dashboards."""
        return {
            "total_events": self.count,
            "buffer_size": len(self._events),
            "max_size": self.max_size,
            "type_statistics": self.type_statistics,
        }

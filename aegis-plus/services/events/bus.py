"""In-process event bus.

A lightweight, synchronous, in-process event dispatcher with ordered delivery,
failure isolation, and observability. Handlers for a given event type are invoked
in registration order; a failing handler is logged but does not prevent the
remaining handlers from executing.

The bus satisfies the Core ``IEventBus`` port. A future async or external-broker
implementation would replace this module behind the same interface.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from core.domain.events import EventType, IntelligenceEvent
from core.interfaces.event_bus import EventHandler, IEventBus
from core.interfaces.logger import ILogger


@dataclass
class _DispatchMetrics:
    """Accumulated dispatch metrics for observability."""

    total_published: int = 0
    total_dispatched: int = 0
    total_failures: int = 0
    total_publish_ms: float = 0.0
    type_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))


class InProcessEventBus(IEventBus):
    """Synchronous, ordered, failure-isolated event dispatcher."""

    def __init__(self, logger: ILogger) -> None:
        """Initialize the bus.

        Args:
            logger: Injected logger for observability.
        """
        self._handlers: dict[EventType, list[EventHandler]] = defaultdict(list)
        self._logger = logger
        self._metrics = _DispatchMetrics()

    def publish(self, event: IntelligenceEvent) -> None:
        """Publish an event to all registered handlers for its type.

        Handlers are invoked synchronously in registration order. A failing
        handler is logged and isolated — it does not prevent subsequent
        handlers from executing.
        """
        start = time.monotonic()
        handlers = self._handlers.get(event.event_type, [])
        self._metrics.total_published += 1
        self._metrics.type_counts[event.event_type.value] += 1

        for handler in handlers:
            self._metrics.total_dispatched += 1
            try:
                handler(event)
            except Exception:
                self._metrics.total_failures += 1
                self._logger.exception(
                    "Event handler failed for {} (event_id={})",
                    event.event_type.value,
                    event.event_id,
                )

        elapsed = (time.monotonic() - start) * 1000
        self._metrics.total_publish_ms += elapsed
        self._logger.debug(
            "Event {} dispatched to {} handler(s) in {:.2f} ms",
            event.event_type.value,
            len(handlers),
            elapsed,
        )

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Register a handler for events of the given type."""
        self._handlers[event_type].append(handler)
        self._logger.debug(
            "Handler registered for {} (total: {})",
            event_type.value,
            len(self._handlers[event_type]),
        )

    def subscriber_count(self, event_type: EventType | None = None) -> int:
        """Return the number of registered handlers."""
        if event_type is not None:
            return len(self._handlers.get(event_type, []))
        return sum(len(handlers) for handlers in self._handlers.values())

    @property
    def metrics(self) -> dict[str, object]:
        """Return accumulated observability metrics."""
        m = self._metrics
        return {
            "total_published": m.total_published,
            "total_dispatched": m.total_dispatched,
            "total_failures": m.total_failures,
            "total_publish_ms": round(m.total_publish_ms, 2),
            "type_counts": dict(m.type_counts),
        }

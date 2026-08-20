"""Internal Intelligence Event Bus.

In-process, synchronous event dispatcher with ordered delivery, failure
isolation, event history, and observability — the foundation for the
event-driven intelligence architecture.
"""

from services.events.bus import InProcessEventBus
from services.events.history import EventHistory

__all__ = ["EventHistory", "InProcessEventBus"]

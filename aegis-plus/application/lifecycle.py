"""Application lifecycle management.

Coordinates startup and shutdown as an explicit state machine and provides a
context-manager interface so callers can guarantee clean shutdown. Transitions
are idempotent: starting a running application or stopping a stopped one is a
no-op.
"""

from __future__ import annotations

from enum import Enum
from types import TracebackType
from typing import TYPE_CHECKING

from application.shutdown import shutdown
from application.startup import startup

if TYPE_CHECKING:
    from application.dependency_container import DependencyContainer


class LifecycleState(str, Enum):
    """The application's lifecycle state."""

    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


class ApplicationLifecycle:
    """Drives the application through its startup and shutdown phases."""

    def __init__(self, container: DependencyContainer) -> None:
        """Initialize the lifecycle.

        Args:
            container: The wired dependency container.
        """
        self._container = container
        self._state = LifecycleState.CREATED

    @property
    def state(self) -> LifecycleState:
        """The current lifecycle state."""
        return self._state

    def start(self) -> None:
        """Run startup, transitioning to RUNNING. No-op if already running."""
        if self._state is LifecycleState.RUNNING:
            return
        self._state = LifecycleState.STARTING
        startup(self._container)
        self._state = LifecycleState.RUNNING

    def stop(self) -> None:
        """Run shutdown, transitioning to STOPPED. No-op if not running."""
        if self._state in (LifecycleState.CREATED, LifecycleState.STOPPED):
            return
        self._state = LifecycleState.STOPPING
        shutdown(self._container)
        self._state = LifecycleState.STOPPED

    def __enter__(self) -> ApplicationLifecycle:
        """Start the application and return the lifecycle."""
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Stop the application on context exit."""
        self.stop()

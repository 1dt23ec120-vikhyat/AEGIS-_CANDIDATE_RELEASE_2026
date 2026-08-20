"""Application facade.

A small facade over the dependency container and lifecycle. It is the object
callers (the desktop entry point in WP7, or tests) interact with to start and
stop AEGIS+ and to query its health.
"""

from __future__ import annotations

from types import TracebackType

from application.dependency_container import DependencyContainer
from application.health import HealthReport
from application.lifecycle import ApplicationLifecycle, LifecycleState


class Application:
    """The assembled AEGIS+ application."""

    def __init__(self, container: DependencyContainer, lifecycle: ApplicationLifecycle) -> None:
        """Initialize the application.

        Args:
            container: The wired dependency container.
            lifecycle: The lifecycle coordinating startup/shutdown.
        """
        self._container = container
        self._lifecycle = lifecycle

    @property
    def container(self) -> DependencyContainer:
        """The dependency container."""
        return self._container

    @property
    def is_running(self) -> bool:
        """Whether the application is running."""
        return self._lifecycle.state is LifecycleState.RUNNING

    @property
    def backend_url(self) -> str:
        """The base URL of the embedded backend."""
        return self._container.backend_server.base_url

    def start(self) -> None:
        """Start the application (idempotent)."""
        self._lifecycle.start()

    def stop(self) -> None:
        """Stop the application (idempotent)."""
        self._lifecycle.stop()

    def health(self) -> HealthReport:
        """Return the current aggregated health report."""
        return self._container.health_registry.run()

    def __enter__(self) -> Application:
        """Start the application and return it."""
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

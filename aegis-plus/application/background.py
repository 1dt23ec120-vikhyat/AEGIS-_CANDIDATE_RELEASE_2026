"""Background service management.

Defines the contract for long-running background services (such as the embedded
backend server) and a manager that starts and stops them in a controlled order
during the application lifecycle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.interfaces import ILogger


class BackgroundService(ABC):
    """A long-running service started and stopped with the application."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The service's stable name."""

    @abstractmethod
    def start(self) -> None:
        """Start the service (idempotent)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop the service (idempotent)."""

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Whether the service is currently running."""


class BackgroundServiceManager:
    """Starts and stops registered background services in order."""

    def __init__(self, logger: ILogger) -> None:
        """Initialize the manager.

        Args:
            logger: Injected logger for lifecycle messages.
        """
        self._logger = logger
        self._services: list[BackgroundService] = []

    def register(self, service: BackgroundService) -> None:
        """Register a background service."""
        self._services.append(service)

    def start_all(self) -> None:
        """Start all services in registration order."""
        for service in self._services:
            self._logger.info("Starting background service: {}", service.name)
            service.start()

    def stop_all(self) -> None:
        """Stop all services in reverse registration order, tolerating errors."""
        for service in reversed(self._services):
            try:
                self._logger.info("Stopping background service: {}", service.name)
                service.stop()
            except Exception as exc:
                self._logger.error("Error stopping {}: {}", service.name, exc)

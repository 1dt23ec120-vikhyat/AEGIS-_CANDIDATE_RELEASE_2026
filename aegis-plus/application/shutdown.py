"""Shutdown orchestration.

Reverses startup: stop background services, then release database resources.
Shutdown is resilient - individual failures are logged and do not prevent the
remaining steps from running.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from application.dependency_container import DependencyContainer


def shutdown(container: DependencyContainer) -> None:
    """Execute the shutdown phases in order.

    Args:
        container: The wired dependency container.
    """
    logger = container.logger("shutdown")
    logger.info("Shutting down")

    container.background_manager.stop_all()
    container.database.dispose()

    logger.info("Shutdown complete")

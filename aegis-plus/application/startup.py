"""Startup orchestration.

Runs the ordered phases required to bring AEGIS+ into a running state: configure
logging, apply database migrations, verify connectivity, start background
services, and record the first audit event. Each phase is explicit and logged so
failures are diagnosable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from infrastructure.database.migrator import apply_migrations
from infrastructure.logging import configure_logging

if TYPE_CHECKING:
    from application.dependency_container import DependencyContainer


def startup(container: DependencyContainer) -> None:
    """Execute the startup phases in order.

    Args:
        container: The wired dependency container.
    """
    settings = container.settings

    # Phase 1 - logging must be configured before anything emits.
    configure_logging(
        settings.logging,
        container.paths,
        environment=settings.application.environment,
    )
    logger = container.logger("startup")
    logger.info(
        "Starting {} v{} ({})",
        settings.application.name,
        settings.application.version,
        settings.application.environment.value,
    )

    # Phase 2 - bring the schema to the latest revision (Alembic is authoritative).
    apply_migrations(container.config_provider.database_url())
    logger.info("Database migrations applied")

    # Phase 3 - verify database connectivity.
    report = container.health_registry.run()
    logger.info("Health check: {}", report.status.value)

    # Phase 4 - start background services (embedded backend).
    container.background_manager.start_all()

    # Phase 5 - record the first audit event through the full persistence path.
    container.audit_logger.success(
        "application.start",
        version=settings.application.version,
        environment=settings.application.environment.value,
    )

    logger.info("Startup complete")

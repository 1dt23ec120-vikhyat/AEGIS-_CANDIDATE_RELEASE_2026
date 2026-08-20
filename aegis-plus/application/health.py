"""Health-check infrastructure.

Provides a small, composable health-check framework used by startup verification
and the backend's readiness endpoint. Individual checks report a status; the
registry aggregates them into an overall result.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from core.interfaces import ILogger
from infrastructure.database import Database


class HealthStatus(str, Enum):
    """Overall or per-check health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    """The outcome of a single health check."""

    name: str
    status: HealthStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class HealthReport:
    """Aggregated health across all registered checks."""

    status: HealthStatus
    checks: list[HealthCheckResult] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        """Whether the overall status is healthy."""
        return self.status is HealthStatus.HEALTHY


class HealthCheck(ABC):
    """A single named health check."""

    @property
    @abstractmethod
    def name(self) -> str:
        """The check's stable name."""

    @abstractmethod
    def check(self) -> HealthCheckResult:
        """Run the check and return its result."""


class DatabaseHealthCheck(HealthCheck):
    """Verifies database connectivity with a trivial query."""

    def __init__(self, database: Database) -> None:
        """Initialize with the database to probe.

        Args:
            database: The database whose connectivity is verified.
        """
        self._database = database

    @property
    def name(self) -> str:
        """The check name."""
        return "database"

    def check(self) -> HealthCheckResult:
        """Attempt a lightweight connection and query."""
        try:
            self._database.ping()
        except Exception as exc:
            return HealthCheckResult(self.name, HealthStatus.UNHEALTHY, str(exc))
        return HealthCheckResult(self.name, HealthStatus.HEALTHY, "connection ok")


class HealthRegistry:
    """Registers health checks and aggregates their results."""

    def __init__(self, logger: ILogger) -> None:
        """Initialize the registry.

        Args:
            logger: Injected logger for recording check outcomes.
        """
        self._logger = logger
        self._checks: list[HealthCheck] = []

    def register(self, check: HealthCheck) -> None:
        """Register a health check."""
        self._checks.append(check)

    def run(self) -> HealthReport:
        """Run all checks and aggregate an overall status.

        The overall status is unhealthy if any check is unhealthy, degraded if
        any check is degraded (and none unhealthy), otherwise healthy.

        Returns:
            The aggregated :class:`HealthReport`.
        """
        results = [check.check() for check in self._checks]
        overall = HealthStatus.HEALTHY
        if any(r.status is HealthStatus.UNHEALTHY for r in results):
            overall = HealthStatus.UNHEALTHY
        elif any(r.status is HealthStatus.DEGRADED for r in results):
            overall = HealthStatus.DEGRADED

        if overall is not HealthStatus.HEALTHY:
            self._logger.warning("Health check reported status: {}", overall.value)
        return HealthReport(status=overall, checks=results)

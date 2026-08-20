"""Unit tests for the health-check infrastructure."""

from __future__ import annotations

import pytest

from application.health import (
    DatabaseHealthCheck,
    HealthCheck,
    HealthCheckResult,
    HealthRegistry,
    HealthStatus,
)
from infrastructure.database import Database
from infrastructure.logging import get_logger

pytestmark = pytest.mark.unit


class _StubCheck(HealthCheck):
    def __init__(self, name: str, status: HealthStatus) -> None:
        self._name = name
        self._status = status

    @property
    def name(self) -> str:
        return self._name

    def check(self) -> HealthCheckResult:
        return HealthCheckResult(self._name, self._status)


def _registry() -> HealthRegistry:
    return HealthRegistry(get_logger("test"))


def test_all_healthy_is_healthy() -> None:
    registry = _registry()
    registry.register(_StubCheck("a", HealthStatus.HEALTHY))
    registry.register(_StubCheck("b", HealthStatus.HEALTHY))
    report = registry.run()
    assert report.status is HealthStatus.HEALTHY
    assert report.is_healthy
    assert len(report.checks) == 2


def test_any_unhealthy_is_unhealthy() -> None:
    registry = _registry()
    registry.register(_StubCheck("a", HealthStatus.HEALTHY))
    registry.register(_StubCheck("b", HealthStatus.UNHEALTHY))
    assert registry.run().status is HealthStatus.UNHEALTHY


def test_degraded_without_unhealthy_is_degraded() -> None:
    registry = _registry()
    registry.register(_StubCheck("a", HealthStatus.HEALTHY))
    registry.register(_StubCheck("b", HealthStatus.DEGRADED))
    assert registry.run().status is HealthStatus.DEGRADED


def test_database_health_check_healthy_on_live_db() -> None:
    database = Database("sqlite:///:memory:")
    result = DatabaseHealthCheck(database).check()
    assert result.status is HealthStatus.HEALTHY


def test_database_health_check_unhealthy_on_bad_db() -> None:
    database = Database("sqlite:////nonexistent_dir_xyz/does_not_exist.db")
    result = DatabaseHealthCheck(database).check()
    assert result.status is HealthStatus.UNHEALTHY

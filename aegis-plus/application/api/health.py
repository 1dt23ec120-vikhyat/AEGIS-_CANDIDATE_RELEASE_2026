"""Health and metadata routes for the embedded backend."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from application.health import HealthRegistry, HealthStatus

_READINESS_STATUS_CODE = {
    HealthStatus.HEALTHY: 200,
    HealthStatus.DEGRADED: 200,
    HealthStatus.UNHEALTHY: 503,
}


def build_router() -> APIRouter:
    """Build the health/metadata router.

    Routes read shared state (app metadata and the health registry) from the
    application instance, so the router carries no dependencies of its own.

    Returns:
        The configured :class:`~fastapi.APIRouter`.
    """
    router = APIRouter()

    @router.get("/")
    def root(request: Request) -> dict[str, Any]:
        """Return backend identity and running state."""
        return {
            "name": request.app.state.app_name,
            "version": request.app.state.app_version,
            "status": "running",
        }

    @router.get("/health")
    def liveness() -> dict[str, str]:
        """Liveness probe: the process is up and serving."""
        return {"status": "ok"}

    @router.get("/health/ready")
    def readiness(request: Request) -> JSONResponse:
        """Readiness probe: dependencies (e.g. database) are usable."""
        registry: HealthRegistry = request.app.state.health_registry
        report = registry.run()
        payload = {
            "status": report.status.value,
            "checks": [
                {"name": c.name, "status": c.status.value, "detail": c.detail}
                for c in report.checks
            ],
        }
        return JSONResponse(content=payload, status_code=_READINESS_STATUS_CODE[report.status])

    return router

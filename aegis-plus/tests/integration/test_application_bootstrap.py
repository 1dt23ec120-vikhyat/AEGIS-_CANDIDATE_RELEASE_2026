"""Integration tests for the composition root and embedded backend."""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from application.app import Application
from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import ProjectPaths, Settings, load_settings
from infrastructure.logging import reset_logging

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    reset_logging()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    (tmp_path / "config").mkdir()
    db_file = tmp_path / "aegis.db"
    return load_settings(
        ProjectPaths.create(root=tmp_path),
        environ={
            "AEGIS_DATABASE_URL": f"sqlite:///{db_file}",
            "AEGIS_BACKEND_PORT": str(_free_port()),
        },
        use_env_file=False,
    )


@pytest.fixture
def application(settings: Settings, tmp_path: Path) -> Iterator[Application]:
    container = DependencyContainer(settings, paths=ProjectPaths.create(root=tmp_path))
    app = Application(container, ApplicationLifecycle(container))
    yield app
    app.stop()


def _authenticate(base_url: str) -> dict[str, str]:
    """Register and log in through the real backend; return an auth header.

    Protected routers require a valid session, so wiring tests must authenticate
    first. This exercises the full register -> login -> bearer-token flow against
    the embedded backend.
    """
    password = "Str0ng!Passw0rd"
    httpx.post(
        f"{base_url}/api/auth/register",
        json={
            "full_name": "Boot Analyst",
            "username": "bootstrap",
            "email": "bootstrap@aegis.local",
            "password": password,
            "confirm_password": password,
        },
        timeout=10.0,
    )
    login = httpx.post(
        f"{base_url}/api/auth/login",
        json={"identifier": "bootstrap", "password": password},
        timeout=10.0,
    )
    token = login.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_application_starts_and_serves_liveness(application: Application) -> None:
    application.start()
    assert application.is_running

    response = httpx.get(f"{application.backend_url}/health", timeout=5.0)
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_healthy_database(application: Application) -> None:
    application.start()

    response = httpx.get(f"{application.backend_url}/health/ready", timeout=5.0)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert any(c["name"] == "database" for c in body["checks"])


def test_root_route_reports_identity(application: Application) -> None:
    application.start()
    response = httpx.get(f"{application.backend_url}/", timeout=5.0)
    assert response.status_code == 200
    assert response.json()["name"] == "AEGIS+"


def test_lifecycle_is_idempotent(application: Application) -> None:
    application.start()
    application.start()  # no-op
    assert application.is_running

    application.stop()
    application.stop()  # no-op
    assert not application.is_running


def test_shutdown_stops_backend(application: Application) -> None:
    application.start()
    server = application.container.backend_server
    assert server.is_running

    application.stop()
    assert not server.is_running


def test_copilot_endpoint_is_wired(application: Application) -> None:
    application.start()
    headers = _authenticate(application.backend_url)
    response = httpx.post(
        f"{application.backend_url}/api/copilot/ask",
        json={"question": "what is the current security posture?"},
        headers=headers,
        timeout=10.0,
    )
    assert response.status_code == 200
    body = response.json()
    # With no API key configured in the test environment, the Copilot degrades
    # gracefully rather than erroring: the platform stays fully operational.
    assert body["available"] is False
    assert "session_id" in body


def test_protected_route_requires_authentication(application: Application) -> None:
    application.start()
    # Without a session the SOC overview must be rejected at the API boundary.
    response = httpx.get(f"{application.backend_url}/api/soc/overview", timeout=5.0)
    assert response.status_code == 401


def test_copilot_health_component_does_not_degrade_platform(
    application: Application,
) -> None:
    application.start()
    headers = _authenticate(application.backend_url)
    body = httpx.get(
        f"{application.backend_url}/api/soc/overview", headers=headers, timeout=5.0
    ).json()
    names = {c["name"] for c in body["health"]}
    assert "ai-copilot" in names
    assert body["platform_status"] == "Operational"


def test_copilot_stream_endpoint_is_wired(application: Application) -> None:
    application.start()
    headers = _authenticate(application.backend_url)
    # With no API key configured, streaming degrades gracefully: the endpoint
    # still responds as an event stream and emits a terminal error event rather
    # than raising. The platform stays fully operational regardless.
    with httpx.stream(
        "POST",
        f"{application.backend_url}/api/copilot/ask/stream",
        json={"question": "what is the current security posture?"},
        headers=headers,
        timeout=10.0,
    ) as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        kinds = []
        for line in response.iter_lines():
            stripped = line.strip()
            if stripped.startswith("data:"):
                payload = json.loads(stripped[len("data:") :].strip())
                kinds.append(payload["kind"])
    assert kinds  # at least one event was emitted
    assert kinds[-1] in ("final", "error")

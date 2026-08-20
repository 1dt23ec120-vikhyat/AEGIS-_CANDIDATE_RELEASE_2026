"""End-to-end integration test for the URL Analysis vertical.

Drives a real request through the running backend: HTTP -> service -> analyzer ->
persistence -> database, and verifies the result is returned, listed, and stored.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import ProjectPaths, Settings, load_settings
from core.entities import UrlScan
from infrastructure.logging import reset_logging
from tests.integration._auth import install_auth

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
def running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[DependencyContainer, str]]:
    (tmp_path / "config").mkdir()
    settings: Settings = load_settings(
        ProjectPaths.create(root=tmp_path),
        environ={
            "AEGIS_DATABASE_URL": f"sqlite:///{tmp_path / 'aegis.db'}",
            "AEGIS_BACKEND_PORT": str(_free_port()),
        },
        use_env_file=False,
    )
    container = DependencyContainer(settings, paths=ProjectPaths.create(root=tmp_path))
    life = ApplicationLifecycle(container)
    life.start()
    install_auth(monkeypatch, container.backend_server.base_url)
    yield container, container.backend_server.base_url
    life.stop()


def test_scan_endpoint_returns_and_persists(
    running: tuple[DependencyContainer, str],
) -> None:
    container, base_url = running
    phishing = "http://192.168.10.5/login@paypal-verify-account-secure.example.com/signin"

    response = httpx.post(f"{base_url}/api/url/scan", json={"url": phishing}, timeout=5.0)
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] in ("suspicious", "phishing")
    assert body["risk_percent"] > 0
    assert len(body["contributions"]) > 0

    recent = httpx.get(f"{base_url}/api/url/scans/recent", timeout=5.0).json()
    assert any(item["url"] == body["url"] for item in recent)

    with container.unit_of_work_factory() as uow:
        stored = uow.get_repository(UrlScan).list()
    assert len(stored) == 1
    assert stored[0].url == body["url"]


def test_benign_url_is_legitimate(running: tuple[DependencyContainer, str]) -> None:
    _, base_url = running
    response = httpx.post(
        f"{base_url}/api/url/scan", json={"url": "https://www.wikipedia.org"}, timeout=5.0
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "legitimate"


def test_invalid_url_rejected(running: tuple[DependencyContainer, str]) -> None:
    _, base_url = running
    response = httpx.post(f"{base_url}/api/url/scan", json={"url": "ftp://x"}, timeout=5.0)
    assert response.status_code == 422

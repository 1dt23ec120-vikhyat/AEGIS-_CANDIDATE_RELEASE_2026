"""End-to-end integration tests for Threat Intelligence & Auto-Protection.

Drives real requests through the running backend: a malicious detection is
auto-blacklisted, a repeat detection is a blacklist hit that skips analysis, and
the protection endpoints (check, guard-open, list, stats, fetch) behave.
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
from infrastructure.logging import reset_logging
from tests.integration._auth import install_auth

pytestmark = pytest.mark.integration

_PHISHING = (
    "http://192.168.10.5/login@paypal-verify-account-update-secure.example.com/signin?password=1"
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    reset_logging()


@pytest.fixture
def base_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
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
    yield container.backend_server.base_url
    life.stop()


def test_malicious_detection_is_blacklisted_and_hits_on_repeat(base_url: str) -> None:
    first = httpx.post(f"{base_url}/api/url/scan", json={"url": _PHISHING}, timeout=5.0)
    assert first.status_code == 200
    body = first.json()
    assert body["verdict"] == "phishing"
    assert body["blacklisted"] is True
    assert body["blacklist_hit"] is False

    # Repeat detection: served from the blacklist, pipeline skipped.
    second = httpx.post(f"{base_url}/api/url/scan", json={"url": _PHISHING}, timeout=5.0)
    assert second.json()["blacklist_hit"] is True

    threats = httpx.get(f"{base_url}/api/threats", timeout=5.0).json()
    assert len(threats) == 1
    assert threats[0]["detection_count"] >= 2
    threat_hash = threats[0]["hash"]

    check = httpx.post(f"{base_url}/api/threats/check", json={"url": _PHISHING}, timeout=5.0)
    assert check.json()["blocked"] is True

    guard = httpx.post(f"{base_url}/api/threats/guard-open", json={"url": _PHISHING}, timeout=5.0)
    assert guard.json()["blocked"] is True

    fetched = httpx.get(f"{base_url}/api/threats/{threat_hash}", timeout=5.0)
    assert fetched.status_code == 200
    assert fetched.json()["url"] == body["url"]


def test_stats_reflect_blacklist(base_url: str) -> None:
    httpx.post(f"{base_url}/api/url/scan", json={"url": _PHISHING}, timeout=5.0)
    stats = httpx.get(f"{base_url}/api/threats/stats", timeout=5.0).json()
    assert stats["total_blacklisted"] == 1
    assert stats["high_risk_count"] == 1
    assert stats["most_recent"] is not None


def test_benign_url_is_not_blocked(base_url: str) -> None:
    httpx.post(f"{base_url}/api/url/scan", json={"url": "https://www.wikipedia.org"}, timeout=5.0)
    check = httpx.post(
        f"{base_url}/api/threats/check", json={"url": "https://www.wikipedia.org"}, timeout=5.0
    )
    assert check.json()["blocked"] is False

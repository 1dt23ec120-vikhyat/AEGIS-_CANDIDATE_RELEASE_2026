"""End-to-end integration tests for the SOC command centre API."""

from __future__ import annotations

import shutil
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import ProjectPaths, Settings, load_settings
from infrastructure.logging import reset_logging
from tests.integration._auth import install_auth

_MODEL = Path(__file__).resolve().parents[2] / "models" / "url_lightgbm.txt"
_AUTH = "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"
_LURE = "Your account is suspended. Click here to verify and reset your password."


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    reset_logging()


@pytest.fixture
def running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    (tmp_path / "config").mkdir()
    if _MODEL.exists():
        (tmp_path / "models").mkdir()
        shutil.copy(_MODEL, tmp_path / "models" / "url_lightgbm.txt")
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


def _overview(base_url: str) -> dict[str, Any]:
    response = httpx.get(f"{base_url}/api/soc/overview", timeout=15.0)
    assert response.status_code == 200
    return dict(response.json())


def _phish(base_url: str, sender: str, subject: str, to: str = "one@corp.com") -> None:
    content = f"From: {sender}\nTo: {to}\nSubject: {subject}\n{_AUTH}\n{_LURE}\n"
    httpx.post(f"{base_url}/api/email/scan", json={"content": content}, timeout=15.0)


def test_overview_on_empty_platform(running: str) -> None:
    body = _overview(running)
    assert body["threat_level"] == "Normal"
    assert body["platform_status"] == "Operational"
    assert body["incident_queue"] == []
    assert body["timeline"] == []
    assert body["health"]


def test_overview_reflects_detections_incidents_and_campaigns(running: str) -> None:
    base_url = running
    _phish(base_url, "PayPal <no-reply@pp-secure.xyz>", "Invoice 4821 overdue")
    _phish(base_url, "PayPal <no-reply@pp-secure.xyz>", "Invoice 9142 overdue", "two@corp.com")

    body = _overview(base_url)
    assert body["threat_level"] in ("Elevated", "Critical")
    assert float(body["risk_score"]) > 0
    assert len(body["incident_queue"]) == 1
    assert len(body["campaigns"]) == 1

    posture = {m["label"]: m["value"] for m in body["posture"]}
    assert posture["Open incidents"] == "1"
    assert posture["Active campaigns"] == "1"
    assert int(posture["Blocked threats"]) >= 1

    timeline = body["timeline"]
    assert timeline
    kinds = {e["kind"] for e in timeline}
    assert "email_analysis" in kinds
    assert "threat_blocked" in kinds


def test_overview_surfaces_threat_intelligence_and_analytics(running: str) -> None:
    base_url = running
    _phish(base_url, "PayPal <no-reply@pp-secure.xyz>", "Verify your account")

    body = _overview(base_url)
    senders = {name for name, _ in body["top_malicious_senders"]}
    assert "no-reply@pp-secure.xyz" in senders
    assert body["artifact_distribution"]
    analytics = {m["label"]: m["value"] for m in body["analytics"]}
    assert int(analytics["Artifacts analyzed"]) >= 1
    assert int(analytics["Detections"]) >= 1
    assert len(body["detection_trend"]) == 7


def test_overview_reflects_analyst_workflow(running: str) -> None:
    base_url = running
    _phish(base_url, "PayPal <no-reply@pp-secure.xyz>", "Verify your account")
    incident_id = httpx.get(f"{base_url}/api/incidents", timeout=10.0).json()[0]["id"]
    httpx.put(
        f"{base_url}/api/incidents/{incident_id}/workflow",
        json={
            "status": "investigating",
            "assignee": "alice",
            "priority": "critical",
            "comment": "Triaging now.",
        },
        timeout=10.0,
    )

    body = _overview(base_url)
    activity = {m["label"]: m["value"] for m in body["analyst_activity"]}
    assert activity["Assigned incidents"] == "1"
    assert activity["Busiest analyst"] == "alice"
    assert body["recent_comments"] == [["analyst", "Triaging now."]]
    incident_metrics = {m["label"]: m["value"] for m in body["incident_metrics"]}
    assert incident_metrics["Investigating"] == "1"


def test_resolution_clears_open_posture(running: str) -> None:
    base_url = running
    _phish(base_url, "PayPal <no-reply@pp-secure.xyz>", "Verify your account")
    incident_id = httpx.get(f"{base_url}/api/incidents", timeout=10.0).json()[0]["id"]
    httpx.put(
        f"{base_url}/api/incidents/{incident_id}/workflow",
        json={"status": "resolved"},
        timeout=10.0,
    )

    body = _overview(base_url)
    assert body["threat_level"] == "Normal"
    assert body["incident_queue"] == []
    incident_metrics = {m["label"]: m["value"] for m in body["incident_metrics"]}
    assert incident_metrics["Open"] == "0"
    assert incident_metrics["Resolved today"] == "1"


def test_health_reports_engine_components(running: str) -> None:
    body = _overview(running)
    names = {h["name"] for h in body["health"]}
    assert {"ml-engine", "heuristic-engine", "threat-intelligence", "configuration"} <= names

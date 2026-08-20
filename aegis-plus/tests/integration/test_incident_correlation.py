"""End-to-end integration tests for incident correlation and campaigns."""

from __future__ import annotations

import shutil
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

_MODEL = Path(__file__).resolve().parents[2] / "models" / "url_lightgbm.txt"
_HEADERS = "Date: Tue, 21 Jul 2026 09:14:00 +0000\nMIME-Version: 1.0\n"
_AUTH = "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _email(sender: str, subject: str, body: str, to: str = "one@corp.com") -> str:
    return f"From: {sender}\nTo: {to}\nSubject: {subject}\n{_HEADERS}{_AUTH}\n{body}\n"


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


def _scan(base_url: str, content: str) -> dict[str, object]:
    response = httpx.post(f"{base_url}/api/email/scan", json={"content": content}, timeout=15.0)
    assert response.status_code == 200
    return dict(response.json())


def test_related_emails_correlate_into_one_incident(running: str) -> None:
    base_url = running
    lure = "Your account is suspended. Click here to verify and reset your password."
    _scan(base_url, _email("PayPal <no-reply@pp-secure.xyz>", "Invoice 4821 overdue", lure))
    _scan(
        base_url,
        _email(
            "PayPal <no-reply@pp-secure.xyz>",
            "Invoice 9142 overdue",
            lure,
            to="two@corp.com",
        ),
    )

    incidents = httpx.get(f"{base_url}/api/incidents", timeout=10.0).json()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["occurrences"] == 2
    assert len(incident["scan_ids"]) == 2
    assert sorted(incident["affected_users"]) == ["one@corp.com", "two@corp.com"]
    labels = [e["label"] for e in incident["events"]]
    assert "Incident created" in labels
    assert "Detection correlated" in labels


def test_unrelated_emails_open_separate_incidents(running: str) -> None:
    base_url = running
    _scan(
        base_url,
        _email(
            "PayPal <no-reply@pp-secure.xyz>",
            "Verify your account",
            "Your account is suspended. Click here to verify and reset your password.",
        ),
    )
    _scan(
        base_url,
        _email(
            "HR <payroll@totally-other.xyz>",
            "Bonus payment",
            "Are you available? Please process this payment via wire transfer.",
        ),
    )
    incidents = httpx.get(f"{base_url}/api/incidents", timeout=10.0).json()
    assert len(incidents) == 2


def test_shared_url_correlates_distinct_senders(running: str) -> None:
    base_url = running
    payload = (
        "Your account is suspended. Click here to verify: "
        "http://192.168.10.5/login@paypal-verify.example.com/signin?password=1"
    )
    _scan(base_url, _email("A <a@first-domain.xyz>", "Security notice", payload))
    _scan(base_url, _email("B <b@second-domain.xyz>", "Account notice", payload))

    incidents = httpx.get(f"{base_url}/api/incidents", timeout=10.0).json()
    assert len(incidents) == 1
    assert incidents[0]["occurrences"] == 2
    kinds = {a["kind"] for a in incidents[0]["artifacts"]}
    assert "url" in kinds
    assert "url_hash" in kinds


def test_campaign_is_discovered_and_grows(running: str) -> None:
    base_url = running
    lure = "Your account is suspended. Click here to verify and reset your password."
    _scan(base_url, _email("PayPal <no-reply@pp-secure.xyz>", "Invoice 1 overdue", lure))
    _scan(base_url, _email("PayPal <no-reply@pp-secure.xyz>", "Invoice 2 overdue", lure))

    campaigns = httpx.get(f"{base_url}/api/campaigns", timeout=10.0).json()
    assert len(campaigns) == 1
    assert campaigns[0]["occurrences"] == 2
    assert campaigns[0]["name"]


def test_relationship_intelligence_reports_shared_artifacts(running: str) -> None:
    base_url = running
    lure = "Your account is suspended. Click here to verify and reset your password."
    _scan(base_url, _email("PayPal <no-reply@pp-secure.xyz>", "Invoice 1 overdue", lure))
    _scan(base_url, _email("PayPal <no-reply@pp-secure.xyz>", "Invoice 2 overdue", lure))

    body = httpx.get(
        f"{base_url}/api/relationships",
        params={"kind": "sender", "value": "no-reply@pp-secure.xyz"},
        timeout=10.0,
    ).json()
    joined = " ".join(body["statements"])
    assert "incident" in joined
    assert "campaign" in joined.lower()

    unknown = httpx.get(
        f"{base_url}/api/relationships",
        params={"kind": "sender", "value": "nobody@nowhere.test"},
        timeout=10.0,
    ).json()
    assert "no known relationships" in " ".join(unknown["statements"]).lower()


def test_analyst_workflow_and_resolution(running: str) -> None:
    base_url = running
    _scan(
        base_url,
        _email(
            "PayPal <no-reply@pp-secure.xyz>",
            "Verify your account",
            "Your account is suspended. Click here to verify and reset your password.",
        ),
    )
    incident_id = httpx.get(f"{base_url}/api/incidents", timeout=10.0).json()[0]["id"]

    updated = httpx.put(
        f"{base_url}/api/incidents/{incident_id}/workflow",
        json={
            "status": "investigating",
            "assignee": "alice",
            "priority": "critical",
            "tags": ["phishing"],
            "comment": "Confirmed credential harvesting.",
        },
        timeout=10.0,
    ).json()
    assert updated["status"] == "investigating"
    assert updated["assignee"] == "alice"
    assert updated["priority"] == "critical"
    assert updated["comments"][0]["author"] == "analyst"

    resolved = httpx.put(
        f"{base_url}/api/incidents/{incident_id}/workflow",
        json={"status": "resolved"},
        timeout=10.0,
    ).json()
    assert resolved["status"] == "resolved"
    # Analyst decisions survive.
    assert resolved["assignee"] == "alice"
    assert resolved["tags"] == ["phishing"]


def test_resolved_incident_does_not_absorb_new_detections(running: str) -> None:
    base_url = running
    lure = "Your account is suspended. Click here to verify and reset your password."
    _scan(base_url, _email("PayPal <no-reply@pp-secure.xyz>", "Invoice 1 overdue", lure))
    incident_id = httpx.get(f"{base_url}/api/incidents", timeout=10.0).json()[0]["id"]
    httpx.put(
        f"{base_url}/api/incidents/{incident_id}/workflow",
        json={"status": "resolved"},
        timeout=10.0,
    )
    _scan(base_url, _email("PayPal <no-reply@pp-secure.xyz>", "Invoice 2 overdue", lure))

    incidents = httpx.get(f"{base_url}/api/incidents", timeout=10.0).json()
    assert len(incidents) == 2


def test_incident_not_found_returns_404(running: str) -> None:
    base_url = running
    response = httpx.get(f"{base_url}/api/incidents/does-not-exist", timeout=10.0)
    assert response.status_code == 404


def test_scan_response_surfaces_correlation(running: str) -> None:
    base_url = running
    lure = "Your account is suspended. Click here to verify and reset your password."
    first = _scan(base_url, _email("PayPal <no-reply@pp.xyz>", "Invoice 1 overdue", lure))
    assert first["incident_id"]
    assert first["campaign_name"]
    assert first["correlation_rationale"] == "New incident opened"

    second = _scan(base_url, _email("PayPal <no-reply@pp.xyz>", "Invoice 2 overdue", lure))
    assert second["incident_id"] == first["incident_id"]
    assert "shared" in str(second["correlation_rationale"]).lower()


def test_safe_email_creates_no_incident(running: str) -> None:
    base_url = running
    _scan(base_url, "From: friend@example.com\nSubject: Lunch\n\nWant to grab lunch?\n")
    assert httpx.get(f"{base_url}/api/incidents", timeout=10.0).json() == []

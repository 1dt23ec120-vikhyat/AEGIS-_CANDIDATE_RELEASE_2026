"""End-to-end integration tests for the email analysis API."""

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
from core.entities import EmailScan
from infrastructure.logging import reset_logging
from tests.integration._auth import install_auth

_MODEL = Path(__file__).resolve().parents[2] / "models" / "url_lightgbm.txt"


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
    yield container, container.backend_server.base_url
    life.stop()


_PHISH = (
    "From: PayPal Support <no-reply@paypal-secure-login.xyz>\n"
    "Reply-To: attacker@evil.example\n"
    "To: you@example.com\n"
    "Subject: Urgent: your account is suspended\n"
    "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n\n"
    "Verify immediately: http://192.168.10.5/login@paypal-verify.example.com/signin\n"
)
_SAFE = "From: colleague@example.com\nSubject: Notes\n\nHere are the notes from today.\n"


def test_email_scan_detects_phishing_and_persists(
    running: tuple[DependencyContainer, str],
) -> None:
    container, base_url = running
    response = httpx.post(f"{base_url}/api/email/scan", json={"content": _PHISH}, timeout=10.0)
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] in ("suspicious", "phishing")
    assert body["risk_percent"] > 0
    assert body["url_count"] >= 1
    assert len(body["sources"]) > 0
    assert any(s["source"] == "url" for s in body["sources"])

    recent = httpx.get(f"{base_url}/api/email/scans/recent", timeout=10.0).json()
    assert any(item["sender"] == body["sender"] for item in recent)

    with container.unit_of_work_factory() as uow:
        stored = uow.get_repository(EmailScan).list()
    assert len(stored) == 1


def test_safe_email_scan_is_not_malicious(
    running: tuple[DependencyContainer, str],
) -> None:
    _, base_url = running
    body = httpx.post(f"{base_url}/api/email/scan", json={"content": _SAFE}, timeout=10.0).json()
    assert body["verdict"] == "legitimate"
    assert not body["malicious"]


def test_invalid_email_returns_422(running: tuple[DependencyContainer, str]) -> None:
    _, base_url = running
    response = httpx.post(f"{base_url}/api/email/scan", json={"content": "   "}, timeout=10.0)
    assert response.status_code == 422


_INVESTIGATION_EMAIL = (
    "From: CEO <ceo@company-invoices.xyz>\n"
    "Reply-To: finance@evil.example\n"
    "To: analyst@example.com\n"
    "Cc: manager@example.com\n"
    "Subject: Urgent wire transfer\n"
    "Date: Tue, 21 Jul 2026 09:14:00 +0000\n"
    "Message-ID: <inv-1@company-invoices.xyz>\n"
    "MIME-Version: 1.0\n"
    "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"
    "Content-Type: multipart/mixed; boundary=B\n\n"
    "--B\nContent-Type: text/plain\n\n"
    "Are you available? Please process this payment via wire transfer.\n"
    "--B\n"
    'Content-Type: application/octet-stream; name="details.pdf.exe"\n'
    'Content-Disposition: attachment; filename="details.pdf.exe"\n\nXX\n'
    "--B--\n"
)


def test_scan_returns_full_investigation_payload(
    running: tuple[DependencyContainer, str],
) -> None:
    _, base_url = running
    body = httpx.post(
        f"{base_url}/api/email/scan", json={"content": _INVESTIGATION_EMAIL}, timeout=10.0
    ).json()

    overview = body["overview"]
    assert overview["message_id"] == "<inv-1@company-invoices.xyz>"
    assert overview["cc"] == ["manager@example.com"]
    assert overview["reply_to"] == "finance@evil.example"

    statuses = {m["name"]: m["status"] for m in body["authentication"]}
    assert statuses == {"SPF": "fail", "DKIM": "fail", "DMARC": "fail"}
    assert all(m["impact"] for m in body["authentication"])

    intel = body["sender_intel"]
    assert intel["reply_to_mismatch"] is True
    assert intel["domain"] == "company-invoices.xyz"

    attachment = body["attachments"][0]
    assert attachment["filename"] == "details.pdf.exe"
    assert attachment["sha256"]
    assert attachment["indicators"]
    assert attachment["malware_scan"] == "not_available"

    assert body["body"]["plain"]
    assert body["body"]["raw"]


def test_investigation_defaults_then_persists(
    running: tuple[DependencyContainer, str],
) -> None:
    _, base_url = running
    scan = httpx.post(
        f"{base_url}/api/email/scan", json={"content": _INVESTIGATION_EMAIL}, timeout=10.0
    ).json()
    scan_id = scan["id"]

    default = httpx.get(f"{base_url}/api/email/investigations/{scan_id}", timeout=10.0).json()
    assert default["status"] == "open"
    assert default["priority"] == "medium"

    saved = httpx.put(
        f"{base_url}/api/email/investigations/{scan_id}",
        json={
            "status": "confirmed_threat",
            "priority": "critical",
            "tags": ["bec", "finance"],
            "notes": "Escalated to IR.",
        },
        timeout=10.0,
    ).json()
    assert saved["status"] == "confirmed_threat"

    reloaded = httpx.get(f"{base_url}/api/email/investigations/{scan_id}", timeout=10.0).json()
    assert reloaded["priority"] == "critical"
    assert reloaded["tags"] == ["bec", "finance"]
    assert reloaded["notes"] == "Escalated to IR."


def test_sender_history_accumulates_across_scans(
    running: tuple[DependencyContainer, str],
) -> None:
    _, base_url = running
    httpx.post(f"{base_url}/api/email/scan", json={"content": _INVESTIGATION_EMAIL}, timeout=10.0)
    second = httpx.post(
        f"{base_url}/api/email/scan", json={"content": _INVESTIGATION_EMAIL}, timeout=10.0
    ).json()
    assert second["sender_intel"]["prior_scans"] >= 1

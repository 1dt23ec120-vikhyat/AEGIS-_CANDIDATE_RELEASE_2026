"""Integration tests for the Gmail connector API (M14).

Exercises ``/api/gmail/*`` over the running backend. The Gmail service's external
boundaries (gateway, auth flow, token store) are replaced with in-memory fakes so
no live OAuth, Gmail, or network is needed. Verifies the AEGIS+ session boundary
(separate from Gmail OAuth), that responses never carry token material, and that
status/sync/disconnect behave correctly — including graceful handling when no
account is connected.
"""

from __future__ import annotations

import shutil
import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import ProjectPaths, Settings, load_settings
from core.domain.gmail import GmailCredentials, GmailMessageRef, GmailRawMessage
from core.interfaces.gmail import IGmailAuthFlow, IGmailGateway, IGmailTokenStore
from infrastructure.logging import reset_logging
from tests.integration._auth import auth_header

_MODEL = Path(__file__).resolve().parents[2] / "models" / "url_lightgbm.txt"
_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
_PHISH = (
    "From: PayPal <no-reply@paypal-secure.xyz>\n"
    "To: victim@example.com\n"
    "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"
    "Subject: Urgent: verify your account\n\n"
    "Suspended. Visit http://paypal-verify-account.xyz/login to reset your password.\n"
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _creds() -> GmailCredentials:
    return GmailCredentials(
        access_token="at",
        refresh_token="rt",
        token_type="Bearer",
        scope=_SCOPE,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


class _FakeGateway(IGmailGateway):
    def __init__(self, messages: dict[str, str]) -> None:
        self._messages = messages

    def profile_email(self, credentials: GmailCredentials) -> str:
        return "analyst@gmail.com"

    def list_messages(
        self, credentials: GmailCredentials, *, query: str, max_results: int
    ) -> tuple[GmailMessageRef, ...]:
        return tuple(
            GmailMessageRef(message_id=m, thread_id=f"t-{m}")
            for m in list(self._messages)[:max_results]
        )

    def fetch_raw(self, credentials: GmailCredentials, message_id: str) -> GmailRawMessage:
        return GmailRawMessage(message_id=message_id, raw=self._messages[message_id])


class _FakeAuth(IGmailAuthFlow):
    def authorize(self) -> GmailCredentials:
        return _creds()

    def refresh(self, credentials: GmailCredentials) -> GmailCredentials:
        return _creds()


class _MemStore(IGmailTokenStore):
    def __init__(self, creds: GmailCredentials | None) -> None:
        self._creds = creds

    def load(self) -> GmailCredentials | None:
        return self._creds

    def save(self, credentials: GmailCredentials) -> None:
        self._creds = credentials

    def clear(self) -> None:
        self._creds = None


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    reset_logging()


@pytest.fixture
def running(tmp_path: Path) -> Iterator[tuple[DependencyContainer, str]]:
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
    yield container, container.backend_server.base_url
    life.stop()


def _inject(container: DependencyContainer, *, messages: dict[str, str], connected: bool) -> None:
    service = container.gmail_service
    service._gateway = _FakeGateway(messages)
    service._auth = _FakeAuth()
    service._tokens = _MemStore(_creds() if connected else None)


def test_status_requires_session(running: tuple[DependencyContainer, str]) -> None:
    _, base = running
    # No Authorization header: the AEGIS+ session boundary rejects the request.
    assert httpx.get(f"{base}/api/gmail/status").status_code == 401


def test_status_connected_has_no_secrets(
    running: tuple[DependencyContainer, str],
) -> None:
    container, base = running
    _inject(container, messages={}, connected=True)
    header = auth_header(base)
    body = httpx.get(f"{base}/api/gmail/status", headers=header).json()
    assert body["connected"] is True
    assert body["read_only"] is True
    assert not any(k in body for k in ("token", "access_token", "refresh_token", "client_secret"))


def test_sync_ingests_via_pipeline(
    running: tuple[DependencyContainer, str],
) -> None:
    container, base = running
    _inject(container, messages={"m1": _PHISH}, connected=True)
    header = auth_header(base)
    result = httpx.post(f"{base}/api/gmail/sync", json={}, headers=header).json()
    assert result["retrieved"] == 1
    assert result["analyzed"] == 1
    assert result["malicious"] == 1


def test_sync_without_connection_is_graceful(
    running: tuple[DependencyContainer, str],
) -> None:
    container, base = running
    _inject(container, messages={}, connected=False)
    header = auth_header(base)
    response = httpx.post(f"{base}/api/gmail/sync", json={}, headers=header)
    assert response.status_code == 502
    assert "detail" in response.json()  # a safe message, not a stack trace


def test_disconnect(running: tuple[DependencyContainer, str]) -> None:
    container, base = running
    _inject(container, messages={}, connected=True)
    header = auth_header(base)
    body = httpx.post(f"{base}/api/gmail/disconnect", headers=header).json()
    assert body["connected"] is False


def test_dedup_across_two_syncs(running: tuple[DependencyContainer, str]) -> None:
    container, base = running
    _inject(container, messages={"m1": _PHISH}, connected=True)
    header = auth_header(base)
    first = httpx.post(f"{base}/api/gmail/sync", json={}, headers=header).json()
    second = httpx.post(f"{base}/api/gmail/sync", json={}, headers=header).json()
    assert first["analyzed"] == 1
    assert second["analyzed"] == 0
    assert second["duplicates"] == 1


def test_messages_requires_session(running: tuple[DependencyContainer, str]) -> None:
    _, base = running
    assert httpx.get(f"{base}/api/gmail/messages").status_code == 401


def test_messages_list_after_sync(running: tuple[DependencyContainer, str]) -> None:
    container, base = running
    _inject(container, messages={"m1": _PHISH}, connected=True)
    header = auth_header(base)
    httpx.post(f"{base}/api/gmail/sync", json={}, headers=header)
    body = httpx.get(f"{base}/api/gmail/messages", headers=header).json()
    assert isinstance(body, list)
    assert len(body) == 1
    row = body[0]
    assert row["message_id"] == "m1"
    assert row["status"] == "analyzed"
    assert row["risk_band"] == "high_risk"
    assert row["risk_percent"] > 0
    # No token material leaks through the list.
    assert not any(k in row for k in ("token", "access_token", "refresh_token"))


def test_message_detail_exposes_existing_analysis(
    running: tuple[DependencyContainer, str],
) -> None:
    container, base = running
    _inject(container, messages={"m1": _PHISH}, connected=True)
    header = auth_header(base)
    httpx.post(f"{base}/api/gmail/sync", json={}, headers=header)
    detail = httpx.get(f"{base}/api/gmail/messages/m1", headers=header).json()
    assert detail["message"]["message_id"] == "m1"
    assert detail["evidence"]  # existing explainable contributions
    assert detail["preview"] is not None
    # The safe preview marks links untrusted and never auto-opens them.
    assert all(u["verdict"] == "untrusted" for u in detail["preview"]["urls"])
    # A scan_id enables opening the existing Email Investigation workspace.
    assert detail["message"]["scan_id"]


def test_message_detail_unknown_id_is_404(running: tuple[DependencyContainer, str]) -> None:
    container, base = running
    _inject(container, messages={}, connected=True)
    header = auth_header(base)
    assert httpx.get(f"{base}/api/gmail/messages/nope", headers=header).status_code == 404


def test_email_scan_by_id_opens_investigation(
    running: tuple[DependencyContainer, str],
) -> None:
    container, base = running
    _inject(container, messages={"m1": _PHISH}, connected=True)
    header = auth_header(base)
    httpx.post(f"{base}/api/gmail/sync", json={}, headers=header)
    detail = httpx.get(f"{base}/api/gmail/messages/m1", headers=header).json()
    scan_id = detail["message"]["scan_id"]
    scan = httpx.get(f"{base}/api/email/scans/{scan_id}", headers=header).json()
    assert scan["id"] == scan_id
    assert scan["verdict"]

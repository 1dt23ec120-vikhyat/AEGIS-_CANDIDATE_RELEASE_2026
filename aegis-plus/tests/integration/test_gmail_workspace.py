"""Gmail Intelligence workspace + read-model tests (M14 completion).

Proves the analyst-facing completion guarantees on top of the **real** email
analysis pipeline from the dependency container (no Gmail-specific intelligence):

- the workspace read-model lists messages with their *existing* verdict/risk,
- the four-state ingestion taxonomy (analyzed / unsupported / transient / failed)
  is applied and a malformed message never fails the whole synchronization,
- deduplication and the read-model are account-aware, so multiple demonstration
  accounts stay isolated across connect/disconnect/reconnect,
- message detail surfaces the existing evidence, IOCs, and incident/campaign
  correlation, and a safe preview,
- Gmail-derived intelligence reaches the existing SOC and knowledge graph.

A configurable fake Gmail gateway/auth/store returns canned raw RFC-822 messages
and a switchable account identity; no network or Google credentials are involved.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import ProjectPaths, Settings, load_settings
from core.domain.gmail import (
    GmailCredentials,
    GmailMessageRef,
    GmailMessageStatus,
    GmailRawMessage,
)
from core.interfaces.gmail import GmailApiError, IGmailAuthFlow, IGmailGateway, IGmailTokenStore
from infrastructure.logging import get_logger, reset_logging
from infrastructure.repositories.gmail_sync_state_repository import (
    SqlAlchemyGmailSyncStateRepository,
)
from services.gmail import GmailIngestionService, GmailSyncStateContext

_PHISH_RAW = (
    "From: PayPal <no-reply@paypal-secure.xyz>\n"
    "To: victim@example.com\n"
    "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"
    "Subject: Urgent: verify your account\n\n"
    "Your account is suspended. Visit http://paypal-verify-account.xyz/login "
    "to verify and reset your password immediately.\n"
)
_SAFE_RAW = (
    "From: friend@example.com\n"
    "To: me@example.com\n"
    "Subject: lunch tomorrow?\n\n"
    "Want to grab lunch tomorrow around noon?\n"
)
# A message whose decoded raw is empty/whitespace — EmailMessage.parse rejects it,
# reproducing the real "unsupported message" case behind the observed "1 error".
_MALFORMED_RAW = "   \n \n"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])


def _creds(scope: str = "https://www.googleapis.com/auth/gmail.readonly") -> GmailCredentials:
    return GmailCredentials(
        access_token="at",
        refresh_token="rt",
        token_type="Bearer",
        scope=scope,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


class _FakeGateway(IGmailGateway):
    """A gateway with a switchable account identity and optional fetch failures."""

    def __init__(self, account_email: str = "account-a@gmail.com") -> None:
        self.account_email = account_email
        self.messages: dict[str, str] = {}
        self.fail: set[str] = set()
        self.fetch_calls: list[str] = []

    def profile_email(self, credentials: GmailCredentials) -> str:
        return self.account_email

    def list_messages(
        self, credentials: GmailCredentials, *, query: str, max_results: int
    ) -> tuple[GmailMessageRef, ...]:
        return tuple(
            GmailMessageRef(
                message_id=mid,
                thread_id=f"t-{mid}",
                subject=f"msg {mid}",
                sender="sender@example.com",
                received_at="Mon, 16 Aug 2026 21:00:00 +0000",
                snippet=f"snippet for {mid}",
            )
            for mid in list(self.messages)[:max_results]
        )

    def fetch_raw(self, credentials: GmailCredentials, message_id: str) -> GmailRawMessage:
        self.fetch_calls.append(message_id)
        if message_id in self.fail:
            raise GmailApiError("temporary Gmail failure")
        return GmailRawMessage(message_id=message_id, raw=self.messages[message_id])


class _FakeAuthFlow(IGmailAuthFlow):
    def authorize(self) -> GmailCredentials:
        return _creds()

    def refresh(self, credentials: GmailCredentials) -> GmailCredentials:
        return _creds()


class _MemoryTokenStore(IGmailTokenStore):
    def __init__(self, connected: bool = True) -> None:
        self._creds: GmailCredentials | None = _creds() if connected else None

    def load(self) -> GmailCredentials | None:
        return self._creds

    def save(self, credentials: GmailCredentials) -> None:
        self._creds = credentials

    def clear(self) -> None:
        self._creds = None


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    reset_logging()
    yield
    reset_logging()


@pytest.fixture
def container(tmp_path: Path) -> Iterator[DependencyContainer]:
    (tmp_path / "config").mkdir()
    settings: Settings = load_settings(
        ProjectPaths.create(root=tmp_path),
        environ={
            "AEGIS_DATABASE_URL": f"sqlite:///{tmp_path / 'aegis.db'}",
            "AEGIS_BACKEND_PORT": str(_free_port()),
        },
        use_env_file=False,
    )
    built = DependencyContainer(settings, paths=ProjectPaths.create(root=tmp_path))
    life = ApplicationLifecycle(built)
    life.start()
    yield built
    life.stop()


def _service(
    container: DependencyContainer,
    gateway: _FakeGateway,
    store: _MemoryTokenStore,
) -> GmailIngestionService:
    session_factory = container.database.session_factory

    def sync_state_factory() -> GmailSyncStateContext:
        session = session_factory()
        return GmailSyncStateContext(
            repository=SqlAlchemyGmailSyncStateRepository(session),
            _commit=session.commit,
            _close=session.close,
        )

    return GmailIngestionService(
        auth_flow=_FakeAuthFlow(),
        token_store=store,
        gateway=gateway,
        email_analysis=container.email_analysis_service,
        sync_state_factory=sync_state_factory,
        logger=get_logger("gmail-workspace-test"),
        incidents=container.incident_service,
        default_query="in:inbox",
        max_messages=50,
    )


# --- read-model list + detail (B, C) ------------------------------------


def test_workspace_lists_messages_with_existing_verdict(container: DependencyContainer) -> None:
    gateway = _FakeGateway()
    gateway.messages = {"m1": _PHISH_RAW, "m2": _SAFE_RAW}
    service = _service(container, gateway, _MemoryTokenStore())

    service.sync()
    messages = service.list_messages()

    assert len(messages) == 2
    by_id = {m.message_id: m for m in messages}
    assert by_id["m1"].status is GmailMessageStatus.ANALYZED
    assert by_id["m1"].risk_band == "high_risk"
    assert by_id["m1"].risk_percent > 0
    assert by_id["m2"].risk_band == "benign"


def test_workspace_filters_and_search(container: DependencyContainer) -> None:
    gateway = _FakeGateway()
    gateway.messages = {"m1": _PHISH_RAW, "m2": _SAFE_RAW}
    service = _service(container, gateway, _MemoryTokenStore())
    service.sync()

    high = service.list_messages(risk_filter="high_risk")
    assert [m.message_id for m in high] == ["m1"]
    benign = service.list_messages(risk_filter="benign")
    assert [m.message_id for m in benign] == ["m2"]
    found = service.list_messages(search="msg m2")
    assert [m.message_id for m in found] == ["m2"]


def test_message_detail_surfaces_existing_evidence_and_preview(
    container: DependencyContainer,
) -> None:
    gateway = _FakeGateway()
    gateway.messages = {"m1": _PHISH_RAW}
    service = _service(container, gateway, _MemoryTokenStore())
    service.sync()

    detail = service.message_detail("m1")

    assert detail is not None
    assert detail.view.status is GmailMessageStatus.ANALYZED
    assert detail.evidence  # existing explainable contributions
    assert detail.preview is not None
    assert not detail.preview.error
    # Safe preview lists URLs as untrusted, never auto-opened.
    assert any(u.verdict == "untrusted" for u in detail.preview.urls)
    assert detail.artifact_id  # graph focus id available
    assert detail.iocs  # sender domain + URL host


def test_message_detail_reports_incident_or_campaign(container: DependencyContainer) -> None:
    gateway = _FakeGateway()
    gateway.messages = {"m1": _PHISH_RAW}
    service = _service(container, gateway, _MemoryTokenStore())
    service.sync()

    detail = service.message_detail("m1")
    assert detail is not None
    # A phishing detection opens an incident via the existing correlation service.
    assert detail.incident_id


# --- four-state taxonomy + the "1 error" (P, Q) -------------------------


def test_malformed_message_is_unsupported_not_a_sync_failure(
    container: DependencyContainer,
) -> None:
    gateway = _FakeGateway()
    gateway.messages = {"good": _SAFE_RAW, "bad": _MALFORMED_RAW}
    service = _service(container, gateway, _MemoryTokenStore())

    result = service.sync()

    assert result.retrieved == 2
    assert result.analyzed == 1
    assert result.unsupported == 1
    assert result.failed == 0
    assert result.errors == 1  # total that could not be analyzed
    # The unsupported message is recorded and analyst-visible, not hidden.
    listed = {m.message_id: m for m in service.list_messages()}
    assert listed["bad"].status is GmailMessageStatus.UNSUPPORTED


def test_transient_failure_is_retried_next_sync(container: DependencyContainer) -> None:
    gateway = _FakeGateway()
    gateway.messages = {"m1": _SAFE_RAW}
    gateway.fail = {"m1"}
    service = _service(container, gateway, _MemoryTokenStore())

    first = service.sync()
    assert first.transient == 1
    assert first.analyzed == 0

    gateway.fail.clear()
    second = service.sync()
    # Not recorded as processed, so it is retried and now analyzed.
    assert second.analyzed == 1
    assert second.duplicates == 0


# --- multi-account isolation + disconnect/reconnect (N, O) --------------


def test_accounts_are_isolated(container: DependencyContainer) -> None:
    store = _MemoryTokenStore()
    gateway = _FakeGateway(account_email="account-a@gmail.com")
    gateway.messages = {"a1": _PHISH_RAW}
    service = _service(container, gateway, store)
    service.sync()
    assert len(service.list_messages()) == 1

    # Switch to a different demonstration account.
    gateway.account_email = "account-b@gmail.com"
    gateway.messages = {"b1": _SAFE_RAW}
    service.sync()

    # Account B sees only its own message; account A's message is not mixed in.
    b_messages = service.list_messages()
    assert [m.message_id for m in b_messages] == ["b1"]


def test_disconnect_clears_state_then_reconnect_is_clean(
    container: DependencyContainer,
) -> None:
    store = _MemoryTokenStore()
    gateway = _FakeGateway()
    gateway.messages = {"m1": _PHISH_RAW}
    service = _service(container, gateway, store)
    service.sync()
    assert service.status().processed_messages == 1

    status = service.disconnect()
    assert status.connected is False

    # Reconnect (new token) and the previous sync state is gone.
    store.save(_creds())
    assert service.list_messages() == ()
    reconnected = service.status()
    assert reconnected.processed_messages == 0


# --- deduplication shows previously-analyzed (M) ------------------------


def test_dedup_keeps_single_record_and_no_refetch(container: DependencyContainer) -> None:
    gateway = _FakeGateway()
    gateway.messages = {"m1": _PHISH_RAW}
    service = _service(container, gateway, _MemoryTokenStore())

    service.sync()
    fetches = list(gateway.fetch_calls)
    second = service.sync()

    assert second.duplicates == 1
    assert second.analyzed == 0
    assert gateway.fetch_calls == fetches  # no re-fetch of processed message
    assert len(service.list_messages()) == 1


# --- SOC + graph participation (K, L) -----------------------------------


def test_gmail_intelligence_reaches_soc_and_graph(container: DependencyContainer) -> None:
    assert container.graph_explorer.snapshot().node_count == 0
    gateway = _FakeGateway()
    gateway.messages = {"m1": _PHISH_RAW}
    service = _service(container, gateway, _MemoryTokenStore())

    service.sync()

    assert container.graph_explorer.snapshot().node_count >= 1
    overview = container.soc_service.overview()
    assert overview is not None

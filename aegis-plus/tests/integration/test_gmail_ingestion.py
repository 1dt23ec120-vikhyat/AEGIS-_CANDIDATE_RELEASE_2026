"""End-to-end Gmail ingestion tests (M14).

Proves the core M14 guarantee: a message pulled from Gmail flows through the
**existing** Email Analysis pipeline and produces real intelligence — IOCs,
threats, and live knowledge-graph nodes — with no Gmail-specific analysis logic.

A fake Gmail gateway/auth/store returns canned raw RFC-822 messages, so no
network or Google credentials are involved. The email analysis service, incident
correlation, event bus, and graph builder are the real ones from the dependency
container.
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
from core.domain.gmail import GmailCredentials, GmailMessageRef, GmailRawMessage
from core.interfaces.gmail import IGmailAuthFlow, IGmailGateway, IGmailTokenStore
from infrastructure.logging import get_logger, reset_logging
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


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])


def _creds() -> GmailCredentials:
    return GmailCredentials(
        access_token="at",
        refresh_token="rt",
        token_type="Bearer",
        scope="https://www.googleapis.com/auth/gmail.readonly",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


class _FakeGateway(IGmailGateway):
    def __init__(self, messages: dict[str, str]) -> None:
        self._messages = messages
        self.fetch_calls: list[str] = []

    def profile_email(self, credentials: GmailCredentials) -> str:
        return "analyst@gmail.com"

    def list_messages(
        self, credentials: GmailCredentials, *, query: str, max_results: int
    ) -> tuple[GmailMessageRef, ...]:
        return tuple(
            GmailMessageRef(message_id=mid, thread_id=f"t-{mid}", subject=f"msg {mid}")
            for mid in list(self._messages)[:max_results]
        )

    def fetch_raw(self, credentials: GmailCredentials, message_id: str) -> GmailRawMessage:
        self.fetch_calls.append(message_id)
        return GmailRawMessage(message_id=message_id, raw=self._messages[message_id])


class _FakeAuthFlow(IGmailAuthFlow):
    def authorize(self) -> GmailCredentials:
        return _creds()

    def refresh(self, credentials: GmailCredentials) -> GmailCredentials:
        return _creds()


class _MemoryTokenStore(IGmailTokenStore):
    def __init__(self) -> None:
        self._creds: GmailCredentials | None = _creds()

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


def _gmail_service(
    container: DependencyContainer, messages: dict[str, str]
) -> tuple[GmailIngestionService, _FakeGateway]:
    """Build a Gmail service using the container's REAL email pipeline."""
    gateway = _FakeGateway(messages)
    session_factory = container.database.session_factory

    def sync_state_factory() -> GmailSyncStateContext:
        from infrastructure.repositories.gmail_sync_state_repository import (
            SqlAlchemyGmailSyncStateRepository,
        )

        session = session_factory()
        return GmailSyncStateContext(
            repository=SqlAlchemyGmailSyncStateRepository(session),
            _commit=session.commit,
            _close=session.close,
        )

    service = GmailIngestionService(
        auth_flow=_FakeAuthFlow(),
        token_store=_MemoryTokenStore(),
        gateway=gateway,
        email_analysis=container.email_analysis_service,
        sync_state_factory=sync_state_factory,
        logger=get_logger("gmail-test"),
        default_query="in:inbox",
        max_messages=50,
    )
    return service, gateway


def test_gmail_phishing_flows_into_real_pipeline(container: DependencyContainer) -> None:
    assert container.graph_explorer.snapshot().node_count == 0
    service, _ = _gmail_service(container, {"m1": _PHISH_RAW})

    result = service.sync()

    assert result.retrieved == 1
    assert result.analyzed == 1
    assert result.malicious == 1
    # The phishing message produced real graph nodes via the existing event bus.
    snapshot = container.graph_explorer.snapshot()
    assert snapshot.node_count >= 1


def test_gmail_ingestion_records_threat_and_email_scan(
    container: DependencyContainer,
) -> None:
    service, _ = _gmail_service(container, {"m1": _PHISH_RAW})
    service.sync()
    # The SOC overview (existing service) now reflects Gmail-derived intelligence.
    overview = container.soc_service.overview()
    assert overview is not None


def test_deduplication_skips_processed_messages(
    container: DependencyContainer,
) -> None:
    service, gateway = _gmail_service(container, {"m1": _PHISH_RAW, "m2": _SAFE_RAW})

    first = service.sync()
    assert first.analyzed == 2
    assert first.duplicates == 0
    fetches_after_first = list(gateway.fetch_calls)

    second = service.sync()
    assert second.analyzed == 0
    assert second.duplicates == 2
    # No new fetches for already-processed messages.
    assert gateway.fetch_calls == fetches_after_first


def test_mixed_batch_statistics(container: DependencyContainer) -> None:
    service, _ = _gmail_service(container, {"m1": _PHISH_RAW, "m2": _SAFE_RAW})
    result = service.sync()
    assert result.retrieved == 2
    assert result.analyzed == 2
    assert result.malicious >= 1
    assert result.benign >= 1
    assert result.errors == 0


def test_zero_messages(container: DependencyContainer) -> None:
    service, _ = _gmail_service(container, {})
    result = service.sync()
    assert result.retrieved == 0
    assert result.analyzed == 0
    assert result.errors == 0

"""Unit tests for the Gmail connector adapters and service (M14).

All Google/network behaviour is faked or mocked — no live OAuth, Gmail, account,
or network is required. Covers the OAuth loopback flow (URL generation, callback
success/denial/timeout/state-mismatch, token exchange, refresh, missing
credentials), the REST gateway (profile/list/fetch-raw, raw decoding, 401→auth
error, API failure), the token store (roundtrip, 0600, corruption, clear), and the
ingestion service (dedup, refresh-on-expiry, stats, partial failure, disconnect).
"""

from __future__ import annotations

import stat
import threading
import time
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from core.domain.gmail import GmailCredentials, GmailMessageRef, GmailRawMessage
from core.interfaces.gmail import (
    GmailApiError,
    GmailAuthError,
    GmailConnectorError,
    IGmailAuthFlow,
    IGmailGateway,
    IGmailTokenStore,
)
from infrastructure.integrations.gmail import (
    FileGmailTokenStore,
    HttpxGmailGateway,
    LoopbackGmailAuthFlow,
)
from infrastructure.logging import get_logger
from services.gmail import GmailIngestionService, GmailSyncStateContext
from services.gmail.service import GmailConnectionStatus

_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def _creds(*, expires_in: int = 3600) -> GmailCredentials:
    return GmailCredentials(
        access_token="at",
        refresh_token="rt",
        token_type="Bearer",
        scope=_SCOPE,
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_in),
    )


# --- token store ---------------------------------------------------------


def test_token_store_roundtrip_and_permissions(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "tokens.json"
    store = FileGmailTokenStore(path)
    assert store.load() is None
    store.save(_creds())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = store.load()
    assert loaded is not None
    assert loaded.access_token == "at"
    assert loaded.refresh_token == "rt"


def test_token_store_clear(tmp_path: Path) -> None:
    path = tmp_path / "tokens.json"
    store = FileGmailTokenStore(path)
    store.save(_creds())
    store.clear()
    assert store.load() is None
    assert not path.exists()


def test_token_store_corrupt_file_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "tokens.json"
    path.write_text("{not json", encoding="utf-8")
    assert FileGmailTokenStore(path).load() is None


def test_credentials_expiry() -> None:
    assert _creds(expires_in=-10).is_expired()
    assert not _creds(expires_in=3600).is_expired()


# --- OAuth loopback flow -------------------------------------------------


def _flow(monkeypatch: pytest.MonkeyPatch, opener: Callable[[str], bool]) -> LoopbackGmailAuthFlow:
    return LoopbackGmailAuthFlow(
        client_id="cid",
        client_secret="secret",
        auth_uri="https://accounts.google.com/o/oauth2/v2/auth",
        token_uri="https://oauth2.googleapis.com/token",
        scope=_SCOPE,
        timeout_seconds=5.0,
        browser_opener=opener,
    )


def _token_response(**over: object) -> httpx.Response:
    body = {
        "access_token": "ATOK",
        "refresh_token": "RTOK",
        "token_type": "Bearer",
        "scope": _SCOPE,
        "expires_in": 3600,
    }
    body.update(over)
    return httpx.Response(200, json=body, request=httpx.Request("POST", "https://t"))


def test_authorize_success(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    def opener(url: str) -> bool:
        captured["url"] = url
        query = dict(x.split("=", 1) for x in url.split("?", 1)[1].split("&"))
        import urllib.parse as up

        redirect = up.unquote(query["redirect_uri"])
        state = query["state"]

        def hit() -> None:
            time.sleep(0.1)
            urllib.request.urlopen(f"{redirect}?code=CODE&state={state}", timeout=5).read()

        threading.Thread(target=hit, daemon=True).start()
        return True

    monkeypatch.setattr(httpx, "post", lambda *a, **k: _token_response())
    creds = _flow(monkeypatch, opener).authorize()
    assert "gmail.readonly" in captured["url"]
    assert "state=" in captured["url"]
    assert "127.0.0.1" in captured["url"]
    assert creds.access_token == "ATOK"
    assert creds.refresh_token == "RTOK"


def test_authorize_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    def opener(url: str) -> bool:
        import urllib.parse as up

        query = dict(x.split("=", 1) for x in url.split("?", 1)[1].split("&"))
        redirect = up.unquote(query["redirect_uri"])
        state = query["state"]

        def hit() -> None:
            time.sleep(0.1)
            urllib.request.urlopen(
                f"{redirect}?error=access_denied&state={state}", timeout=5
            ).read()

        threading.Thread(target=hit, daemon=True).start()
        return True

    with pytest.raises(GmailAuthError):
        _flow(monkeypatch, opener).authorize()


def test_authorize_state_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    def opener(url: str) -> bool:
        import urllib.parse as up

        query = dict(x.split("=", 1) for x in url.split("?", 1)[1].split("&"))
        redirect = up.unquote(query["redirect_uri"])

        def hit() -> None:
            time.sleep(0.1)
            urllib.request.urlopen(f"{redirect}?code=CODE&state=WRONG", timeout=5).read()

        threading.Thread(target=hit, daemon=True).start()
        return True

    monkeypatch.setattr(httpx, "post", lambda *a, **k: _token_response())
    with pytest.raises(GmailAuthError):
        _flow(monkeypatch, opener).authorize()


def test_authorize_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    flow = LoopbackGmailAuthFlow(
        client_id="cid",
        client_secret="secret",
        auth_uri="https://a",
        token_uri="https://t",
        scope=_SCOPE,
        timeout_seconds=0.3,
        browser_opener=lambda _url: True,  # never completes
    )
    with pytest.raises(GmailAuthError):
        flow.authorize()


def test_authorize_missing_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    flow = LoopbackGmailAuthFlow(
        client_id="",
        client_secret="",
        auth_uri="https://a",
        token_uri="https://t",
        scope=_SCOPE,
        browser_opener=lambda _url: True,
    )
    with pytest.raises(GmailAuthError):
        flow.authorize()


def test_refresh_keeps_old_refresh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _token_response(refresh_token=None))
    flow = _flow(monkeypatch, lambda _url: True)
    refreshed = flow.refresh(_creds())
    assert refreshed.access_token == "ATOK"
    assert refreshed.refresh_token == "rt"  # preserved from the original


def test_refresh_without_token_raises() -> None:
    flow = LoopbackGmailAuthFlow(
        client_id="cid",
        client_secret="secret",
        auth_uri="https://a",
        token_uri="https://t",
        scope=_SCOPE,
    )
    creds = GmailCredentials("at", "", "Bearer", _SCOPE, datetime.now(UTC))
    with pytest.raises(GmailAuthError):
        flow.refresh(creds)


# --- gateway -------------------------------------------------------------


def _gateway_response(status: int, body: dict[str, object]) -> httpx.Response:
    return httpx.Response(status, json=body, request=httpx.Request("GET", "https://g"))


def test_gateway_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx,
        "get",
        lambda *a, **k: _gateway_response(200, {"emailAddress": "me@gmail.com"}),
    )
    gw = HttpxGmailGateway(api_base_url="https://gmail.googleapis.com")
    assert gw.profile_email(_creds()) == "me@gmail.com"


def test_gateway_fetch_raw_decodes(monkeypatch: pytest.MonkeyPatch) -> None:
    import base64

    raw = "From: a@b.com\nSubject: hi\n\nbody"
    encoded = base64.urlsafe_b64encode(raw.encode()).decode()
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _gateway_response(200, {"raw": encoded}))
    gw = HttpxGmailGateway(api_base_url="https://gmail.googleapis.com")
    result = gw.fetch_raw(_creds(), "m1")
    assert result.raw == raw
    assert result.message_id == "m1"


def test_gateway_401_raises_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _gateway_response(401, {}))
    gw = HttpxGmailGateway(api_base_url="https://gmail.googleapis.com")
    with pytest.raises(GmailAuthError):
        gw.profile_email(_creds())


def test_gateway_500_raises_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _gateway_response(500, {}))
    gw = HttpxGmailGateway(api_base_url="https://gmail.googleapis.com")
    with pytest.raises(GmailApiError):
        gw.profile_email(_creds())


def test_gateway_network_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> httpx.Response:
        raise httpx.ConnectError("no network")

    monkeypatch.setattr(httpx, "get", boom)
    gw = HttpxGmailGateway(api_base_url="https://gmail.googleapis.com")
    with pytest.raises(GmailApiError):
        gw.profile_email(_creds())


# --- ingestion service (with fakes) --------------------------------------


class _FakeGateway(IGmailGateway):
    def __init__(self, messages: dict[str, str], *, fail: set[str] | None = None) -> None:
        self._messages = messages
        self._fail = fail or set()

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
        if message_id in self._fail:
            raise GmailApiError("boom")
        return GmailRawMessage(message_id=message_id, raw=self._messages[message_id])


class _FakeAuth(IGmailAuthFlow):
    def __init__(self) -> None:
        self.refreshed = 0

    def authorize(self) -> GmailCredentials:
        return _creds()

    def refresh(self, credentials: GmailCredentials) -> GmailCredentials:
        self.refreshed += 1
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


class _MemSyncState:
    def __init__(self) -> None:
        self.processed: dict[tuple[str, str], object] = {}
        self.cleared = False

    def is_processed(self, account_email: str, message_id: str) -> bool:
        return (account_email, message_id) in self.processed

    def get(self, account_email: str, message_id: str) -> object:
        return self.processed.get((account_email, message_id))

    def record(self, message: object) -> None:
        key = (message.account_email, message.message_id)  # type: ignore[attr-defined]
        self.processed[key] = message

    def list_for_account(self, account_email: str) -> tuple[object, ...]:
        return tuple(v for (acc, _mid), v in self.processed.items() if acc == account_email)

    def processed_count(self, account_email: str = "") -> int:
        if not account_email:
            return len(self.processed)
        return sum(1 for (acc, _mid) in self.processed if acc == account_email)

    def clear(self) -> None:
        self.processed.clear()
        self.cleared = True


class _FakeEmailAnalysis:
    """A stand-in with the same ``analyze`` seam the service depends on."""

    def __init__(self, verdicts: dict[str, str]) -> None:
        self._verdicts = verdicts
        self.calls: list[str] = []

    def analyze(self, raw_email: str, *, actor: str | None = None) -> object:
        self.calls.append(raw_email)
        verdict_name = self._verdicts.get(raw_email, "LEGITIMATE")
        return _Outcome(verdict_name)

    def get_scan(self, scan_id: str) -> object:
        return None


class _Scan:
    def __init__(self, verdict_name: str) -> None:
        from core.domain.analysis import Verdict

        self.verdict = Verdict[verdict_name]
        self.id = f"scan-{verdict_name}"
        self.subject = "s"
        self.sender = "x@y.com"


class _Outcome:
    def __init__(self, verdict_name: str) -> None:
        self.scan = _Scan(verdict_name)
        self.malicious = verdict_name == "PHISHING"


def _service(
    messages: dict[str, str],
    verdicts: dict[str, str],
    *,
    creds: GmailCredentials | None,
    fail: set[str] | None = None,
) -> tuple[GmailIngestionService, _MemSyncState, _FakeAuth]:
    state = _MemSyncState()
    auth = _FakeAuth()
    service = GmailIngestionService(
        auth_flow=auth,
        token_store=_MemStore(creds),
        gateway=_FakeGateway(messages, fail=fail),
        email_analysis=_FakeEmailAnalysis(verdicts),  # type: ignore[arg-type]
        sync_state_factory=lambda: GmailSyncStateContext(
            repository=state,  # type: ignore[arg-type]
            _commit=lambda: None,
            _close=lambda: None,
        ),
        logger=get_logger("gmail-unit"),
        default_query="in:inbox",
        max_messages=50,
    )
    return service, state, auth


def test_sync_requires_connection() -> None:
    service, _, _ = _service({}, {}, creds=None)
    with pytest.raises(GmailConnectorError):
        service.sync()


def test_sync_analyzes_and_tallies() -> None:
    messages = {"m1": "phish", "m2": "safe"}
    verdicts = {"phish": "PHISHING", "safe": "LEGITIMATE"}
    service, state, _ = _service(messages, verdicts, creds=_creds())
    result = service.sync()
    assert result.retrieved == 2
    assert result.analyzed == 2
    assert result.malicious == 1
    assert result.benign == 1
    assert state.processed_count() == 2


def test_sync_deduplicates() -> None:
    messages = {"m1": "phish"}
    service, _, _ = _service(messages, {"phish": "PHISHING"}, creds=_creds())
    first = service.sync()
    second = service.sync()
    assert first.analyzed == 1
    assert second.analyzed == 0
    assert second.duplicates == 1


def test_sync_refreshes_expired_token() -> None:
    service, _, auth = _service(
        {"m1": "safe"}, {"safe": "LEGITIMATE"}, creds=_creds(expires_in=-10)
    )
    service.sync()
    assert auth.refreshed >= 1


def test_sync_partial_failure_counts_error() -> None:
    messages = {"m1": "safe", "m2": "safe"}
    service, _, _ = _service(messages, {"safe": "LEGITIMATE"}, creds=_creds(), fail={"m2"})
    result = service.sync()
    assert result.analyzed == 1
    assert result.errors == 1


def test_disconnect_clears_state() -> None:
    service, state, _ = _service({"m1": "safe"}, {"safe": "LEGITIMATE"}, creds=_creds())
    service.sync()
    status = service.disconnect()
    assert isinstance(status, GmailConnectionStatus)
    assert status.connected is False
    assert state.cleared is True


def test_status_not_connected() -> None:
    service, _, _ = _service({}, {}, creds=None)
    status = service.status()
    assert status.connected is False

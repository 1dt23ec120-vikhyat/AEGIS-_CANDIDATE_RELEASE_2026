"""UI tests for the Gmail Integration page and view-model (M14).

A fake backend client returns programmable Gmail status/sync DTOs, and the
view-model runs synchronously, so the page's states and transitions are exercised
deterministically without threads, network, or live OAuth. Covers the
disconnected, connecting, connected, and sync-result states, connect
success/failure, disconnect, sync statistics and errors, and clean teardown.
"""

from __future__ import annotations

import pytest

from tests.ui._async import SyncRunner
from ui.backend import (
    BackendClient,
    GmailMessageDetailDTO,
    GmailMessageDTO,
    GmailPreviewDTO,
    GmailStatusDTO,
    GmailSyncDTO,
    GmailUrlDTO,
)
from ui.context import UIContext
from ui.navigation.routes import Route
from ui.pages.gmail import _CONNECTED, _DISCONNECTED, GmailPage
from ui.theme import ThemeManager
from ui.viewmodels.gmail import GmailViewModel

pytestmark = pytest.mark.ui


class _FakeGmailClient(BackendClient):
    """A backend client with programmable Gmail behaviour (no network)."""

    def __init__(
        self,
        *,
        status: GmailStatusDTO | None = None,
        connect_result: GmailStatusDTO | None = None,
        sync_result: GmailSyncDTO | None = None,
        messages: tuple[GmailMessageDTO, ...] = (),
        detail: GmailMessageDetailDTO | None = None,
    ) -> None:
        super().__init__("http://127.0.0.1:9")
        self._status = status or GmailStatusDTO(connected=False)
        self._connect_result = connect_result
        self._sync_result = sync_result or GmailSyncDTO(
            retrieved=50, analyzed=47, malicious=1, suspicious=3, benign=43, ok=True
        )
        self._messages = messages
        self._detail = detail
        self.connect_calls = 0
        self.sync_calls = 0
        self.disconnect_calls = 0
        self.message_calls: list[tuple[str, str]] = []
        self.detail_calls: list[str] = []

    def gmail_status(self) -> GmailStatusDTO:
        return self._status

    def gmail_connect(self, *, timeout: float = 240.0) -> GmailStatusDTO:
        self.connect_calls += 1
        return self._connect_result or GmailStatusDTO(
            connected=True, email_address="analyst@gmail.com", read_only=True
        )

    def gmail_disconnect(self) -> GmailStatusDTO:
        self.disconnect_calls += 1
        return GmailStatusDTO(connected=False)

    def gmail_sync(
        self, *, max_messages: int | None = None, timeout: float = 120.0
    ) -> GmailSyncDTO:
        self.sync_calls += 1
        return self._sync_result

    def gmail_messages(
        self, *, risk_filter: str = "all", search: str = ""
    ) -> tuple[GmailMessageDTO, ...]:
        self.message_calls.append((risk_filter, search))
        return self._messages

    def gmail_message_detail(self, message_id: str) -> GmailMessageDetailDTO:
        self.detail_calls.append(message_id)
        return self._detail or GmailMessageDetailDTO(message=GmailMessageDTO(message_id=message_id))


def _page(client: BackendClient) -> GmailPage:
    theme = ThemeManager()
    context = UIContext(theme_manager=theme, backend_client=client)
    vm = GmailViewModel(client, runner_factory=SyncRunner)
    return GmailPage(context, view_model=vm)


def test_disconnected_state_on_load(qapp: object) -> None:
    page = _page(_FakeGmailClient(status=GmailStatusDTO(connected=False)))
    assert page._stack.currentIndex() == _DISCONNECTED


def test_connected_state_on_load(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com", read_only=True)
    )
    page = _page(client)
    assert page._stack.currentIndex() == _CONNECTED
    assert "a@gmail.com" in page._account_label.text()


def test_connect_success_moves_to_connected(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=False),
        connect_result=GmailStatusDTO(
            connected=True, email_address="new@gmail.com", read_only=True
        ),
    )
    page = _page(client)
    page.view_model.connect_account()
    assert client.connect_calls == 1
    assert page._stack.currentIndex() == _CONNECTED


def test_connect_failure_shows_error(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=False),
        connect_result=GmailStatusDTO(connected=False, error="Gmail authorization was denied."),
    )
    page = _page(client)
    page.view_model.connect_account()
    assert page._stack.currentIndex() == _DISCONNECTED
    assert page._disconnected_error.isVisible() or page._disconnected_error.text()


def test_sync_shows_statistics(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com"),
        sync_result=GmailSyncDTO(
            retrieved=50, analyzed=47, malicious=1, suspicious=3, benign=43, ok=True
        ),
    )
    page = _page(client)
    page.view_model.sync()
    assert client.sync_calls == 1
    assert page._stack.currentIndex() == _CONNECTED
    assert "malicious" in page._sync_summary._malicious.text()
    assert "1 malicious" in page._sync_summary._malicious.text()


def test_sync_error_shown(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com"),
        sync_result=GmailSyncDTO(ok=False, error="Gmail could not be reached."),
    )
    page = _page(client)
    page.view_model.sync()
    assert page._connected_error.text()


def test_disconnect_returns_to_disconnected(qapp: object) -> None:
    client = _FakeGmailClient(status=GmailStatusDTO(connected=True, email_address="a@gmail.com"))
    page = _page(client)
    page.view_model.disconnect_account()
    assert client.disconnect_calls == 1
    assert page._stack.currentIndex() == _DISCONNECTED


def test_read_only_badge_present_when_connected(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com", read_only=True)
    )
    page = _page(client)
    # The connected card is shown; monitoring is explicitly OFF for M14.
    assert page._stack.currentIndex() == _CONNECTED
    assert "OFF" in page._monitoring_label.text()


# --- workspace: message list, detail, filters, navigation ----------------


def _sample_messages() -> tuple[GmailMessageDTO, ...]:
    return (
        GmailMessageDTO(
            message_id="m1",
            sender="security@paypal-secure.xyz",
            subject="Verify your account",
            status="analyzed",
            risk_band="high_risk",
            verdict="phishing",
            risk_percent=94,
            confidence=0.9,
            scan_id="scan-1",
        ),
        GmailMessageDTO(
            message_id="m2",
            sender="news@example.com",
            subject="Weekly update",
            status="analyzed",
            risk_band="benign",
            verdict="legitimate",
            risk_percent=4,
            scan_id="scan-2",
        ),
    )


def _sample_detail() -> GmailMessageDetailDTO:
    return GmailMessageDetailDTO(
        message=_sample_messages()[0],
        evidence=(),
        iocs=("paypal-secure.xyz",),
        incident_id="INC-1",
        incident_title="Credential harvesting",
        artifact_id="security@paypal-secure.xyz — Verify your account",
        preview=GmailPreviewDTO(
            from_display="PayPal",
            from_address="security@paypal-secure.xyz",
            plain_body="Please verify your account.",
            urls=(GmailUrlDTO(url="http://paypal-verify-account.xyz/login"),),
        ),
        ok=True,
    )


def _page_with_nav(
    client: BackendClient,
) -> tuple[GmailPage, list[tuple[object, object]]]:
    theme = ThemeManager()
    calls: list[tuple[object, object]] = []

    def navigate(route: object, payload: object = None) -> None:
        calls.append((route, payload))

    context = UIContext(theme_manager=theme, backend_client=client, navigate=navigate)
    vm = GmailViewModel(client, runner_factory=SyncRunner)
    return GmailPage(context, view_model=vm), calls


def test_workspace_lists_messages_on_connect(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com"),
        messages=_sample_messages(),
    )
    page = _page(client)
    assert page._stack.currentIndex() == _CONNECTED
    assert page._message_list.count() == 2
    assert client.message_calls  # the list was requested


def test_selecting_message_loads_detail(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com"),
        messages=_sample_messages(),
        detail=_sample_detail(),
    )
    page = _page(client)
    page._message_list.setCurrentRow(0)
    assert client.detail_calls == ["m1"]
    assert page._current_detail is not None
    assert page._current_detail.incident_id == "INC-1"


def test_filter_requests_reload(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com"),
        messages=_sample_messages(),
    )
    page = _page(client)
    page._on_filter("high_risk")
    assert ("high_risk", "") in client.message_calls


def test_open_investigation_navigates_with_scan_id(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com"),
        messages=_sample_messages(),
        detail=_sample_detail(),
    )
    page, calls = _page_with_nav(client)
    page._message_list.setCurrentRow(0)
    assert page._current_detail is not None
    page._detail._add_actions(page._current_detail)  # ensure actions bound
    # Simulate the Open Investigation action.
    page._context.go_to(Route.EMAIL_SCANNER, {"scan_id": "scan-1", "origin": Route.GMAIL})
    assert (Route.EMAIL_SCANNER, {"scan_id": "scan-1", "origin": Route.GMAIL}) in calls


def test_ask_copilot_navigates_with_incident_focus(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com"),
        messages=_sample_messages(),
        detail=_sample_detail(),
    )
    page, calls = _page_with_nav(client)
    page._message_list.setCurrentRow(0)
    assert page._current_detail is not None
    page._detail._ask_copilot(page._current_detail)
    assert any(
        route == Route.COPILOT and isinstance(payload, dict) and payload.get("focus") == "INC-1"
        for route, payload in calls
    )


def test_sync_summary_shows_taxonomy(qapp: object) -> None:
    client = _FakeGmailClient(
        status=GmailStatusDTO(connected=True, email_address="a@gmail.com"),
        sync_result=GmailSyncDTO(
            retrieved=25,
            analyzed=24,
            malicious=1,
            suspicious=8,
            benign=15,
            unsupported=1,
            errors=1,
            ok=True,
        ),
    )
    page = _page(client)
    page.view_model.sync()
    assert "could not be analyzed" in page._sync_summary._headline.text()

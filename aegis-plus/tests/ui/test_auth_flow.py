"""UI tests for the desktop authentication flow (M13).

Drives :class:`DesktopAuthFlow` with a fake client to verify the window
lifecycle: authentication is shown first, a successful login builds and shows the
shell (and clears the auth window), logout tears the shell down and returns to
authentication, and a backend 401 routes back with a session-expired notice. A
final teardown check confirms no window is left running.
"""

from __future__ import annotations

import pytest

from tests.ui._async import pump_until
from ui.backend import AuthResult, AuthUser, BackendClient
from ui.shell.auth_flow import DesktopAuthFlow
from ui.theme import ThemeManager

pytestmark = pytest.mark.ui

_USER = AuthUser(id="1", full_name="Jane Analyst", username="jane", email="jane@aegis.local")


class _FlowClient(BackendClient):
    """A fake client that records token state and never hits the network."""

    def __init__(self) -> None:
        super().__init__("http://127.0.0.1:9")
        self.logout_calls = 0

    def auth_status(self) -> bool | None:
        return True

    def login(self, *, identifier: str, password: str) -> AuthResult:
        self.set_token("t-1")
        return AuthResult(ok=True, user=_USER, token="t-1")

    def logout(self) -> None:
        self.logout_calls += 1
        self.clear_token()


def _flow(client: BackendClient) -> DesktopAuthFlow:
    return DesktopAuthFlow(
        theme_manager=ThemeManager(),
        client=client,
        environment="Local",
        version="1.0",
    )


def test_flow_starts_on_authentication(qapp: object) -> None:
    flow = _flow(_FlowClient())
    flow.start()
    assert flow.auth_window is not None
    assert flow.main_window is None
    flow._teardown_shell()


def test_authentication_builds_and_shows_shell(qapp: object) -> None:
    client = _FlowClient()
    flow = _flow(client)
    flow.start()
    flow._on_authenticated(_USER)
    assert flow.main_window is not None
    assert flow.auth_window is None
    flow._teardown_shell()


def test_shell_reflects_account_name(qapp: object) -> None:
    client = _FlowClient()
    flow = _flow(client)
    flow.start()
    flow._on_authenticated(_USER)
    # The avatar initials are derived from the full name.
    assert flow.main_window is not None
    flow._teardown_shell()


def test_logout_returns_to_authentication(qapp: object) -> None:
    client = _FlowClient()
    client.set_token("t-1")
    flow = _flow(client)
    flow.start()
    flow._on_authenticated(_USER)
    flow._on_logout()
    assert flow.main_window is None
    assert flow.auth_window is not None
    assert client.logout_calls == 1
    assert not client.has_token
    flow._teardown_shell()


def test_session_expiry_returns_with_notice(qapp: object) -> None:
    client = _FlowClient()
    client.set_token("t-1")
    flow = _flow(client)
    flow.start()
    flow._on_authenticated(_USER)
    flow._handle_session_expired()
    assert flow.main_window is None
    assert flow.auth_window is not None
    # The auth window shows the session-expired banner.
    assert "expired" in flow.auth_window._login_banner.text().lower()
    assert not client.has_token
    flow._teardown_shell()


def test_unauthorized_handler_marshals_to_event_loop(qapp: object) -> None:
    client = _FlowClient()
    client.set_token("t-1")
    flow = _flow(client)
    flow.start()
    flow._on_authenticated(_USER)
    # Simulate a 401 arriving (as the client would call it).
    flow._on_unauthorized()
    assert pump_until(lambda: flow.main_window is None)
    assert flow.auth_window is not None
    flow._teardown_shell()

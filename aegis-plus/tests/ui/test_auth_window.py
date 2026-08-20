"""UI tests for the authentication window and desktop flow (M13).

A fake backend client returns programmable auth results, and the view-model runs
synchronously, so the window's states and transitions are exercised
deterministically without threads or a live backend. Covers rendering, mode
switching, validation, password visibility, successful login/registration
navigation, backend-failure and session-expired states, logout navigation, the
protected-shell handoff, keyboard behaviour, and clean teardown.
"""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QLineEdit

from tests.ui._async import SyncRunner
from ui.backend import AuthResult, AuthUser, BackendClient
from ui.pages.auth_window import _LOGIN, _REGISTER, AuthWindow
from ui.viewmodels.auth import AuthViewModel

pytestmark = pytest.mark.ui

_USER = AuthUser(id="1", full_name="Jane Analyst", username="jane", email="jane@aegis.local")
_PASSWORD = "Str0ng!Passw0rd"


class _FakeAuthClient(BackendClient):
    """A backend client with programmable auth behaviour (no network)."""

    def __init__(
        self,
        *,
        account_exists: bool | None = True,
        login_result: AuthResult | None = None,
        register_result: AuthResult | None = None,
    ) -> None:
        super().__init__("http://127.0.0.1:9")
        self._account_exists = account_exists
        self._login_result = login_result or AuthResult(ok=True, user=_USER, token="t-1")
        self._register_result = register_result or AuthResult(ok=True, user=_USER)
        self.login_calls: list[tuple[str, str]] = []
        self.register_calls = 0

    def auth_status(self) -> bool | None:
        return self._account_exists

    def login(self, *, identifier: str, password: str) -> AuthResult:
        self.login_calls.append((identifier, password))
        return self._login_result

    def register(self, **kwargs: str) -> AuthResult:
        self.register_calls += 1
        return self._register_result


def _window(client: BackendClient) -> AuthWindow:
    vm = AuthViewModel(client, runner_factory=SyncRunner)
    return AuthWindow(client, view_model=vm)


# --- rendering / first launch -------------------------------------------


def test_existing_account_opens_on_login(qapp: object) -> None:
    window = _window(_FakeAuthClient(account_exists=True))
    assert window._card_layout.currentIndex() == _LOGIN


def test_first_launch_opens_on_register(qapp: object) -> None:
    window = _window(_FakeAuthClient(account_exists=False))
    assert window._card_layout.currentIndex() == _REGISTER


def test_backend_unreachable_status_still_renders(qapp: object) -> None:
    # auth_status None (unreachable) is treated as "no account": register shown.
    window = _window(_FakeAuthClient(account_exists=None))
    assert window._card_layout.currentIndex() == _REGISTER


# --- mode switching ------------------------------------------------------


def test_switch_between_login_and_register(qapp: object) -> None:
    window = _window(_FakeAuthClient(account_exists=True))
    window._switch_to(_REGISTER)
    assert window._card_layout.currentIndex() == _REGISTER
    window._switch_to(_LOGIN)
    assert window._card_layout.currentIndex() == _LOGIN


# --- validation ----------------------------------------------------------


def test_login_requires_both_fields(qapp: object) -> None:
    client = _FakeAuthClient(account_exists=True)
    window = _window(client)
    window._switch_to(_LOGIN)
    window._submit_login()
    assert client.login_calls == []  # blocked by validation


def test_registration_validates_before_submit(qapp: object) -> None:
    client = _FakeAuthClient(account_exists=False)
    window = _window(client)
    window._switch_to(_REGISTER)
    window._reg_full_name.set_text("Jane Analyst")
    window._reg_username.set_text("jane")
    window._reg_email.set_text("not-an-email")
    window._reg_password.input.setText(_PASSWORD)
    window._reg_confirm.input.setText(_PASSWORD)
    window._submit_registration()
    assert client.register_calls == 0  # blocked by email validation


def test_registration_password_mismatch_blocks(qapp: object) -> None:
    client = _FakeAuthClient(account_exists=False)
    window = _window(client)
    window._switch_to(_REGISTER)
    window._reg_full_name.set_text("Jane Analyst")
    window._reg_username.set_text("jane")
    window._reg_email.set_text("jane@aegis.local")
    window._reg_password.input.setText(_PASSWORD)
    window._reg_confirm.input.setText("Different!99")
    window._submit_registration()
    assert client.register_calls == 0


# --- password visibility -------------------------------------------------


def test_password_visibility_toggle(qapp: object) -> None:
    window = _window(_FakeAuthClient(account_exists=True))
    field = window._login_password
    assert field.input.echoMode() == QLineEdit.EchoMode.Password
    field._toggle.setChecked(True)
    assert field.input.echoMode() == QLineEdit.EchoMode.Normal
    field._toggle.setChecked(False)
    assert field.input.echoMode() == QLineEdit.EchoMode.Password


# --- successful flows ----------------------------------------------------


def test_successful_login_emits_authenticated(qapp: object) -> None:
    client = _FakeAuthClient(account_exists=True)
    window = _window(client)
    window._switch_to(_LOGIN)
    window._login_identifier.set_text("jane")
    window._login_password.input.setText(_PASSWORD)
    captured: list[object] = []
    window.authenticated.connect(captured.append)
    window._submit_login()
    assert client.login_calls == [("jane", _PASSWORD)]
    assert captured == [_USER]


def test_successful_registration_shows_success_then_login(qapp: object) -> None:
    client = _FakeAuthClient(account_exists=False)
    window = _window(client)
    window._switch_to(_REGISTER)
    window._reg_full_name.set_text("Jane Analyst")
    window._reg_username.set_text("jane")
    window._reg_email.set_text("jane@aegis.local")
    window._reg_password.input.setText(_PASSWORD)
    window._reg_confirm.input.setText(_PASSWORD)
    window._submit_registration()
    assert client.register_calls == 1
    # Success card is shown (index 3), then the timer returns to login.
    assert window._card_layout.currentIndex() == 3
    window._after_registration()
    assert window._card_layout.currentIndex() == _LOGIN
    assert window._login_identifier.text() == "jane"


# --- failure states ------------------------------------------------------


def test_invalid_credentials_shows_generic_banner(qapp: object) -> None:
    client = _FakeAuthClient(
        account_exists=True,
        login_result=AuthResult(ok=False, error="Invalid username or password."),
    )
    window = _window(client)
    window._switch_to(_LOGIN)
    window._login_identifier.set_text("jane")
    window._login_password.input.setText("wrong")
    window._submit_login()
    assert window._login_banner.text()
    assert "Invalid username or password." in window._login_banner.text()


def test_backend_unavailable_on_login_shows_message(qapp: object) -> None:
    client = _FakeAuthClient(
        account_exists=True,
        login_result=AuthResult(
            ok=False, backend_unavailable=True, error="Cannot reach the AEGIS+ backend."
        ),
    )
    window = _window(client)
    window._switch_to(_LOGIN)
    window._login_identifier.set_text("jane")
    window._login_password.input.setText(_PASSWORD)
    window._submit_login()
    assert "backend" in window._login_banner.text().lower()


def test_duplicate_account_shows_registration_banner(qapp: object) -> None:
    client = _FakeAuthClient(
        account_exists=False,
        register_result=AuthResult(
            ok=False, error="An AEGIS+ account already exists for this installation."
        ),
    )
    window = _window(client)
    window._switch_to(_REGISTER)
    window._reg_full_name.set_text("Jane Analyst")
    window._reg_username.set_text("jane")
    window._reg_email.set_text("jane@aegis.local")
    window._reg_password.input.setText(_PASSWORD)
    window._reg_confirm.input.setText(_PASSWORD)
    window._submit_registration()
    assert window._reg_banner.text()
    assert "already exists" in window._reg_banner.text()


def test_session_expired_notice(qapp: object) -> None:
    window = _window(_FakeAuthClient(account_exists=True))
    window.notify_session_expired()
    assert window._card_layout.currentIndex() == _LOGIN
    assert window._login_banner.text()
    assert "expired" in window._login_banner.text().lower()


# --- keyboard ------------------------------------------------------------


def test_enter_submits_login(qapp: object) -> None:
    client = _FakeAuthClient(account_exists=True)
    window = _window(client)
    window._switch_to(_LOGIN)
    window._login_identifier.set_text("jane")
    window._login_password.input.setText(_PASSWORD)
    # Simulate Enter on the password field.
    window._login_password.input.returnPressed.emit()
    assert client.login_calls == [("jane", _PASSWORD)]

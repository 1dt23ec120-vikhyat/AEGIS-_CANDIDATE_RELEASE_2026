"""Authentication window (M13).

The entrance to AEGIS+. A polished, branded composition presented before the
application shell: a hero panel carrying the AEGIS+ identity beside a card that
hosts the login and registration forms. It is a pure view over
:class:`~ui.viewmodels.auth.AuthViewModel`: it collects input, reflects the
view-model's state, and emits :attr:`authenticated` once a session is
established. It contains no authentication logic.

States handled: initial loading, login, registration, authenticating,
registration-in-progress, invalid credentials, validation error, account already
exists, backend unavailable, session expired, successful registration, and
successful login. Logout returns here via the shell.
"""

from __future__ import annotations

from itertools import pairwise

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QStackedLayout,
    QVBoxLayout,
    QWidget,
)

from core.security.auth_policy import (
    normalize_registration,
    validate_registration,
)
from ui.backend import AuthResult, BackendClient
from ui.components.auth_fields import FormField, PasswordField, PasswordStrengthMeter
from ui.components.buttons import Button
from ui.icons import render_icon
from ui.theme.tokens import DARK
from ui.viewmodels.auth import AuthViewModel

_LOGIN = 0
_REGISTER = 1


class AuthWindow(QWidget):
    """The login / registration window shown before the application shell."""

    # Emitted with the authenticated user once a session is established.
    authenticated = Signal(object)  # AuthUser

    def __init__(
        self,
        client: BackendClient,
        *,
        view_model: AuthViewModel | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Build the authentication window.

        Args:
            client: Backend gateway (used to build the view-model by default).
            view_model: Optional injected view-model (tests supply a deterministic
                one); by default the window builds its own.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self.setObjectName("AuthWindow")
        self.setWindowTitle("AEGIS+ — Sign in")
        self.setMinimumSize(960, 720)

        self._vm = view_model if view_model is not None else AuthViewModel(client)
        self._session_expired = False
        self._prefill_identifier = ""
        self._success_timer = QTimer(self)
        self._success_timer.setSingleShot(True)
        self._success_timer.timeout.connect(self._after_registration)

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_hero(), 5)
        root.addWidget(self._build_form_panel(), 4)

        self._connect_vm()
        self._show_loading(True)
        self._vm.check_status()

    # --- hero panel ------------------------------------------------------

    def _build_hero(self) -> QWidget:
        hero = QWidget()
        hero.setObjectName("AuthHero")
        layout = QVBoxLayout(hero)
        layout.setContentsMargins(56, 56, 56, 48)
        layout.setSpacing(0)

        brand = QHBoxLayout()
        brand.setSpacing(12)
        mark = QLabel()
        mark.setPixmap(render_icon("shield", size=40, color=DARK.primary))
        brand.addWidget(mark)
        wordmark = QLabel("AEGIS+")
        wordmark.setObjectName("HeroWordmark")
        brand.addWidget(wordmark)
        brand.addStretch(1)
        layout.addLayout(brand)

        layout.addStretch(1)

        headline = QLabel("Security intelligence,\nfrom signal to response.")
        headline.setObjectName("HeroHeadline")
        headline.setWordWrap(True)
        layout.addWidget(headline)

        subhead = QLabel(
            "Detect phishing and identity attacks, investigate across a live "
            "intelligence graph, and drive automated response — all in one "
            "local, private workspace."
        )
        subhead.setObjectName("HeroSubhead")
        subhead.setWordWrap(True)
        layout.addWidget(subhead)

        layout.addSpacing(28)
        for text in (
            "Multi-layer URL, email, and file threat analysis",
            "Correlated incidents, campaigns, and attack paths",
            "Grounded AI Security Copilot",
        ):
            layout.addWidget(self._hero_point(text))

        layout.addStretch(2)

        footer = QLabel("Secure Local Intelligence Environment")
        footer.setObjectName("HeroFooter")
        layout.addWidget(footer)
        return hero

    def _hero_point(self, text: str) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 6, 0, 6)
        layout.setSpacing(12)
        dot = QLabel()
        dot.setPixmap(render_icon("shield", size=18, color=DARK.primary))
        dot.setFixedWidth(20)
        layout.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
        label = QLabel(text)
        label.setObjectName("HeroPoint")
        label.setWordWrap(True)
        layout.addWidget(label, 1)
        return row

    # --- form panel ------------------------------------------------------

    def _build_form_panel(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("AuthFormPanel")
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(48, 48, 48, 48)
        outer.addStretch(1)

        card = QWidget()
        card.setObjectName("AuthCard")
        card.setFixedWidth(420)
        card.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 12)
        shadow.setColor(QColor(0, 0, 0, 150))
        card.setGraphicsEffect(shadow)

        self._card_layout = QStackedLayout(card)
        self._card_layout.addWidget(self._build_login_card())
        self._card_layout.addWidget(self._build_register_card())
        self._card_layout.addWidget(self._build_loading_card())
        self._card_layout.addWidget(self._build_success_card())

        holder = QHBoxLayout()
        holder.addStretch(1)
        holder.addWidget(card)
        holder.addStretch(1)
        outer.addLayout(holder)
        outer.addStretch(1)
        return panel

    def _build_login_card(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 36, 36, 36)
        layout.setSpacing(0)

        title = QLabel("Welcome back")
        title.setObjectName("AuthTitle")
        layout.addWidget(title)
        subtitle = QLabel("Sign in to your AEGIS+ workspace.")
        subtitle.setObjectName("AuthSubtitle")
        layout.addWidget(subtitle)
        layout.addSpacing(24)

        self._login_identifier = FormField("Email or username", placeholder="you@example.com")
        layout.addWidget(self._login_identifier)
        layout.addSpacing(16)

        self._login_password = PasswordField("Password")
        layout.addWidget(self._login_password)
        layout.addSpacing(8)

        self._login_banner = QLabel("")
        self._login_banner.setObjectName("AuthBanner")
        self._login_banner.setWordWrap(True)
        self._login_banner.setVisible(False)
        layout.addWidget(self._login_banner)
        layout.addSpacing(12)

        self._login_button = Button("Sign in", variant="primary")
        self._login_button.setMinimumHeight(46)
        self._login_button.clicked.connect(self._submit_login)
        layout.addWidget(self._login_button)
        layout.addSpacing(18)

        switch = QHBoxLayout()
        switch.addStretch(1)
        prompt = QLabel("New to AEGIS+?")
        prompt.setObjectName("AuthMuted")
        switch.addWidget(prompt)
        self._to_register = _LinkLabel("Create an account")
        self._to_register.clicked.connect(lambda: self._switch_to(_REGISTER))
        switch.addWidget(self._to_register)
        switch.addStretch(1)
        layout.addLayout(switch)

        self._login_identifier.input.returnPressed.connect(self._submit_login)
        self._login_password.input.returnPressed.connect(self._submit_login)
        self.setTabOrder(self._login_identifier.input, self._login_password.input)
        self.setTabOrder(self._login_password.input, self._login_button)
        return page

    def _build_register_card(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 32, 36, 32)
        layout.setSpacing(0)

        title = QLabel("Create your account")
        title.setObjectName("AuthTitle")
        layout.addWidget(title)
        subtitle = QLabel("Set up the local AEGIS+ account for this installation.")
        subtitle.setObjectName("AuthSubtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        layout.addSpacing(20)

        self._add_register_fields(layout)

        self._reg_banner = QLabel("")
        self._reg_banner.setObjectName("AuthBanner")
        self._reg_banner.setWordWrap(True)
        self._reg_banner.setVisible(False)
        layout.addWidget(self._reg_banner)
        layout.addSpacing(2)

        self._register_button = Button("Create account", variant="primary")
        self._register_button.setMinimumHeight(46)
        self._register_button.clicked.connect(self._submit_registration)
        layout.addWidget(self._register_button)
        layout.addSpacing(16)

        switch = QHBoxLayout()
        switch.addStretch(1)
        prompt = QLabel("Already have an account?")
        prompt.setObjectName("AuthMuted")
        switch.addWidget(prompt)
        self._to_login = _LinkLabel("Sign in")
        self._to_login.clicked.connect(lambda: self._switch_to(_LOGIN))
        switch.addWidget(self._to_login)
        switch.addStretch(1)
        layout.addLayout(switch)

        self._reg_password.input.textChanged.connect(self._reg_strength.evaluate)
        self._wire_register_keyboard()
        return page

    def _add_register_fields(self, layout: QVBoxLayout) -> None:
        self._reg_full_name = FormField("Full name", placeholder="Jane Analyst")
        layout.addWidget(self._reg_full_name)
        layout.addSpacing(2)

        self._reg_username = FormField("Username", placeholder="jane.analyst")
        layout.addWidget(self._reg_username)
        layout.addSpacing(2)

        self._reg_email = FormField("Email", placeholder="you@example.com")
        layout.addWidget(self._reg_email)
        layout.addSpacing(2)

        self._reg_password = PasswordField("Password", placeholder="Create a strong password")
        layout.addWidget(self._reg_password)
        self._reg_strength = PasswordStrengthMeter()
        layout.addWidget(self._reg_strength)
        layout.addSpacing(2)

        self._reg_confirm = PasswordField("Confirm password", placeholder="Re-enter password")
        layout.addWidget(self._reg_confirm)
        layout.addSpacing(8)

    def _wire_register_keyboard(self) -> None:
        self._reg_confirm.input.returnPressed.connect(self._submit_registration)
        for field in (
            self._reg_full_name.input,
            self._reg_username.input,
            self._reg_email.input,
        ):
            field.returnPressed.connect(self._focus_next_from)
        self._chain_tab_order(
            [
                self._reg_full_name.input,
                self._reg_username.input,
                self._reg_email.input,
                self._reg_password.input,
                self._reg_confirm.input,
                self._register_button,
            ]
        )

    def _build_loading_card(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 60, 36, 60)
        layout.setSpacing(16)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark = QLabel()
        mark.setPixmap(render_icon("shield", size=48, color=DARK.primary))
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(mark)
        self._loading_label = QLabel("Preparing secure workspace…")
        self._loading_label.setObjectName("AuthSubtitle")
        self._loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._loading_label)
        return page

    def _build_success_card(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(36, 56, 36, 56)
        layout.setSpacing(14)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark = QLabel()
        mark.setPixmap(render_icon("shield", size=52, color=DARK.success))
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(mark)
        self._success_title = QLabel("Your AEGIS+ account has been created.")
        self._success_title.setObjectName("AuthTitle")
        self._success_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._success_title.setWordWrap(True)
        layout.addWidget(self._success_title)
        self._success_subtitle = QLabel("Redirecting you to sign in…")
        self._success_subtitle.setObjectName("AuthSubtitle")
        self._success_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._success_subtitle)
        return page

    # --- view-model integration -----------------------------------------

    def _connect_vm(self) -> None:
        self._vm.status_resolved.connect(self._on_status)
        self._vm.busy_changed.connect(self._on_busy)
        self._vm.login_succeeded.connect(self._on_login_success)
        self._vm.login_failed.connect(self._on_login_failed)
        self._vm.registration_succeeded.connect(self._on_registration_success)
        self._vm.registration_failed.connect(self._on_registration_failed)

    @property
    def view_model(self) -> AuthViewModel:
        """The window's view-model (exposed for tests)."""
        return self._vm

    def _on_status(self, account_exists: bool) -> None:
        self._show_loading(False)
        self._switch_to(_LOGIN if account_exists else _REGISTER)

    def _on_busy(self, busy: bool) -> None:
        current = self._card_layout.currentIndex()
        # During the initial status check the login/register cards are not shown
        # (the loading card is), so leave their buttons in their resting state.
        if current == _LOGIN:
            self._login_button.setEnabled(not busy)
            self._login_button.setText("Signing in…" if busy else "Sign in")
        elif current == _REGISTER:
            self._register_button.setEnabled(not busy)
            self._register_button.setText("Creating account…" if busy else "Create account")

    def _on_login_success(self, result: object) -> None:
        if isinstance(result, AuthResult) and result.user is not None:
            self.authenticated.emit(result.user)

    def _on_login_failed(self, result: object) -> None:
        if not isinstance(result, AuthResult):
            return
        message = result.error if result.backend_unavailable else "Invalid username or password."
        self._login_password.input.clear()
        self._show_banner(self._login_banner, message)
        self._login_identifier.input.setFocus()

    def _on_registration_success(self, result: object) -> None:
        self._card_layout.setCurrentIndex(3)
        # Prefill the login identifier for a smooth transition, then return.
        if isinstance(result, AuthResult) and result.user is not None:
            self._prefill_identifier = result.user.username
        else:
            self._prefill_identifier = ""
        # A page-owned single-shot timer (never a dangling global singleShot), so
        # it is torn down with the window and cannot fire into a destroyed view.
        self._success_timer.start(1400)

    def _after_registration(self) -> None:
        self._reset_register_form()
        self._switch_to(_LOGIN)
        if self._prefill_identifier:
            self._login_identifier.set_text(self._prefill_identifier)
            self._login_password.input.setFocus()

    def _on_registration_failed(self, result: object) -> None:
        if not isinstance(result, AuthResult):
            return
        self._clear_register_field_errors()
        if result.field_errors:
            self._apply_register_field_errors(result.field_errors)
        message = result.error or "Registration could not be completed."
        self._show_banner(self._reg_banner, message)

    # --- actions ---------------------------------------------------------

    def _submit_login(self) -> None:
        if self._vm.is_busy:
            return
        self._hide_banner(self._login_banner)
        identifier = self._login_identifier.text().strip()
        password = self._login_password.text()
        has_error = False
        if not identifier:
            self._login_identifier.set_error("Enter your email or username.")
            has_error = True
        else:
            self._login_identifier.clear_error()
        if not password:
            self._login_password.set_error("Enter your password.")
            has_error = True
        else:
            self._login_password.clear_error()
        if has_error:
            return
        self._vm.login(identifier, password)

    def _submit_registration(self) -> None:
        if self._vm.is_busy:
            return
        self._hide_banner(self._reg_banner)
        self._clear_register_field_errors()
        data = normalize_registration(
            full_name=self._reg_full_name.text(),
            username=self._reg_username.text(),
            email=self._reg_email.text(),
            password=self._reg_password.text(),
        )
        outcome = validate_registration(data, confirm_password=self._reg_confirm.text())
        if not outcome.ok:
            self._apply_register_field_errors(outcome.errors)
            return
        self._vm.register(
            full_name=data.full_name,
            username=data.username,
            email=data.email,
            password=data.password,
            confirm_password=self._reg_confirm.text(),
        )

    def notify_session_expired(self) -> None:
        """Show the session-expired banner and return to the login form."""
        self._session_expired = True
        self._show_loading(False)
        self._switch_to(_LOGIN)
        self._show_banner(self._login_banner, "Your session has expired. Please sign in again.")

    # --- helpers ---------------------------------------------------------

    def _switch_to(self, index: int) -> None:
        self._card_layout.setCurrentIndex(index)
        if index == _LOGIN:
            if not self._session_expired:
                self._hide_banner(self._login_banner)
            self._session_expired = False
            self._login_identifier.input.setFocus()
        else:
            self._hide_banner(self._reg_banner)
            self._reg_full_name.input.setFocus()

    def _show_loading(self, loading: bool) -> None:
        if loading:
            self._card_layout.setCurrentIndex(2)

    def _reset_register_form(self) -> None:
        for field in (
            self._reg_full_name,
            self._reg_username,
            self._reg_email,
        ):
            field.clear()
        self._reg_password.clear()
        self._reg_confirm.clear()
        self._reg_strength.evaluate("")

    def _clear_register_field_errors(self) -> None:
        self._reg_full_name.clear_error()
        self._reg_username.clear_error()
        self._reg_email.clear_error()
        self._reg_password.clear_error()
        self._reg_confirm.clear_error()

    def _apply_register_field_errors(self, errors: dict[str, str]) -> None:
        mapping = {
            "full_name": self._reg_full_name,
            "username": self._reg_username,
            "email": self._reg_email,
        }
        for key, widget in mapping.items():
            if key in errors:
                widget.set_error(errors[key])
        if "password" in errors:
            self._reg_password.set_error(errors["password"])
        if "confirm_password" in errors:
            self._reg_confirm.set_error(errors["confirm_password"])

    def _show_banner(self, banner: QLabel, message: str) -> None:
        banner.setText(message)
        banner.setVisible(True)

    def _hide_banner(self, banner: QLabel) -> None:
        banner.clear()
        banner.setVisible(False)

    def _focus_next_from(self) -> None:
        self.focusNextChild()

    def _chain_tab_order(self, widgets: list[QWidget]) -> None:
        for first, second in pairwise(widgets):
            self.setTabOrder(first, second)


class _LinkLabel(QLabel):
    """A clickable, link-styled label used for switching auth modes."""

    clicked = Signal()

    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        """Initialize the link label."""
        super().__init__(text, parent)
        self.setObjectName("AuthLink")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, event: object) -> None:  # noqa: N802 - Qt override
        """Emit :attr:`clicked` on press."""
        self.clicked.emit()

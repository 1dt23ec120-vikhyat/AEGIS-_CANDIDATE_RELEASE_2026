"""Desktop authentication flow (M13).

Coordinates the entrance sequence: the authentication window is shown first, and
only after a session is established is the application shell built and shown.
Logout tears the shell down and returns to authentication; a backend 401 during
normal use routes back to authentication with a session-expired notice.

The controller owns strong references to the active windows so they are not
garbage-collected while shown, and ensures the shell's background services and
the backend client's unauthorized handler are wired and unwired at the right
moments.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, QTimer

from ui.backend import AuthUser, BackendClient
from ui.context import UIContext
from ui.pages.auth_window import AuthWindow
from ui.shell.main_window import MainWindow
from ui.theme import ThemeManager


class DesktopAuthFlow(QObject):
    """Owns the auth-window ↔ main-window lifecycle for the desktop app."""

    def __init__(
        self,
        *,
        theme_manager: ThemeManager,
        client: BackendClient,
        environment: str,
        version: str,
    ) -> None:
        """Initialize the flow.

        Args:
            theme_manager: Shared theme manager.
            client: Backend client (auth token lives here).
            environment: Environment label for the shell status bar.
            version: Version label for the shell status bar.
        """
        super().__init__()
        self._theme_manager = theme_manager
        self._client = client
        self._environment = environment
        self._version = version
        self._auth_window: AuthWindow | None = None
        self._main_window: MainWindow | None = None

    def start(self) -> None:
        """Show the authentication window (the application entrance)."""
        self._show_auth()

    @property
    def auth_window(self) -> AuthWindow | None:
        """The active authentication window, if shown."""
        return self._auth_window

    @property
    def main_window(self) -> MainWindow | None:
        """The active main window, if shown."""
        return self._main_window

    # --- authentication --------------------------------------------------

    def _show_auth(self, *, session_expired: bool = False) -> None:
        window = AuthWindow(self._client)
        window.authenticated.connect(self._on_authenticated)
        self._auth_window = window
        window.show()
        if session_expired:
            window.notify_session_expired()

    def _on_authenticated(self, user: object) -> None:
        if not isinstance(user, AuthUser):
            return
        self._build_and_show_shell(user)
        if self._auth_window is not None:
            self._auth_window.close()
            self._auth_window = None

    # --- shell -----------------------------------------------------------

    def _build_and_show_shell(self, user: AuthUser) -> None:
        context = UIContext(theme_manager=self._theme_manager, backend_client=self._client)
        window = MainWindow(context, environment=self._environment, version=self._version)
        window.set_account(user.full_name)
        window.logout_requested.connect(self._on_logout)
        # A backend 401 during normal use means the session lapsed: route back to
        # authentication. The handler is marshalled onto the UI thread because it
        # may fire from a worker performing a backend call.
        self._client.set_unauthorized_handler(self._on_unauthorized)
        self._main_window = window
        window.show()
        window.start_services()

    def _on_logout(self) -> None:
        self._client.set_unauthorized_handler(None)
        self._client.logout()
        self._teardown_shell()
        self._show_auth()

    def _on_unauthorized(self) -> None:
        # Defer to the event loop so this is safe to call from a worker thread.
        QTimer.singleShot(0, self._handle_session_expired)

    def _handle_session_expired(self) -> None:
        if self._main_window is None:
            return
        self._client.set_unauthorized_handler(None)
        self._client.clear_token()
        self._teardown_shell()
        self._show_auth(session_expired=True)

    def _teardown_shell(self) -> None:
        window = self._main_window
        if window is not None:
            window.stop_services()
            window.close()
            # Drop our reference and let Python/Qt collect it after the event
            # loop settles; deleting eagerly can race an in-flight worker signal.
            self._main_window = None

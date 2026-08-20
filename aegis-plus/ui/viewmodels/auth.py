"""Authentication view-model (M13).

MVVM view-model for the authentication window. It owns the presentation state of
the login and registration flows, performs all backend access through
:class:`BackendClient` on a worker thread, and exposes results to the window via
Qt signals. It holds no authentication logic — hashing, validation, and session
management all live behind the backend — and never stores the password beyond the
in-flight request.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, Signal

from ui.backend import AsyncRunner, AuthResult, BackendClient
from ui.viewmodels.base import ViewModel

RunnerFactory = Callable[[QObject], AsyncRunner]


class AuthViewModel(ViewModel):
    """Drives login, registration, and first-launch account detection."""

    # Emitted with the resolved first-launch state: True when an account exists.
    status_resolved = Signal(bool)
    # Emitted while a backend call is in flight (True) and when it completes.
    busy_changed = Signal(bool)
    # Login outcomes.
    login_succeeded = Signal(object)  # AuthResult
    login_failed = Signal(object)  # AuthResult
    # Registration outcomes.
    registration_succeeded = Signal(object)  # AuthResult
    registration_failed = Signal(object)  # AuthResult

    def __init__(
        self,
        client: BackendClient,
        *,
        runner_factory: RunnerFactory = AsyncRunner,
    ) -> None:
        """Initialize the view-model.

        Args:
            client: Backend gateway for auth requests.
            runner_factory: Builds the worker that runs backend calls off the UI
                thread. Tests can inject a synchronous runner.
        """
        super().__init__()
        self._client = client
        self._runner = runner_factory(self)
        self._runner.finished.connect(self._on_result)
        self._busy = False
        self._pending = ""

    @property
    def is_busy(self) -> bool:
        """Whether a backend call is currently in flight."""
        return self._busy

    def check_status(self) -> None:
        """Resolve whether a local account already exists (first-launch check)."""
        self._pending = "status"
        self._set_busy(True)
        self._runner.run(self._client.auth_status)

    def login(self, identifier: str, password: str) -> None:
        """Attempt a login with the given identifier and password."""
        if self._busy:
            return
        self._pending = "login"
        self._set_busy(True)
        self._runner.run(lambda: self._client.login(identifier=identifier, password=password))

    def register(
        self,
        *,
        full_name: str,
        username: str,
        email: str,
        password: str,
        confirm_password: str,
    ) -> None:
        """Attempt to register the single local account."""
        if self._busy:
            return
        self._pending = "register"
        self._set_busy(True)
        self._runner.run(
            lambda: self._client.register(
                full_name=full_name,
                username=username,
                email=email,
                password=password,
                confirm_password=confirm_password,
            )
        )

    # --- internals -------------------------------------------------------

    def _on_result(self, result: object) -> None:
        pending, self._pending = self._pending, ""
        self._set_busy(False)
        if pending == "status":
            # None (backend unreachable) is treated as "no account" so the UI
            # still shows a usable screen; the window surfaces connectivity via
            # its own health handling.
            self.status_resolved.emit(bool(result))
            return
        if not isinstance(result, AuthResult):
            return
        if pending == "login":
            (self.login_succeeded if result.ok else self.login_failed).emit(result)
        elif pending == "register":
            (self.registration_succeeded if result.ok else self.registration_failed).emit(result)

    def _set_busy(self, busy: bool) -> None:
        if busy != self._busy:
            self._busy = busy
            self.busy_changed.emit(busy)

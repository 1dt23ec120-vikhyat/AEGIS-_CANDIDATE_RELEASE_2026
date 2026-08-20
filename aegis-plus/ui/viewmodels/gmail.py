"""Gmail connector view-model (M14).

MVVM view-model for the Gmail Integration page. It owns the presentation state of
the connector and performs all backend access through :class:`BackendClient` on a
worker thread, so the OAuth connect flow (which opens the system browser and waits
for the loopback callback) and synchronization never block the UI. Results are
delivered to the page via Qt signals. It holds no connector logic and never sees
an OAuth token — only the safe status/sync DTOs.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, Signal

from ui.backend import (
    AsyncRunner,
    BackendClient,
    GmailMessageDetailDTO,
    GmailStatusDTO,
    GmailSyncDTO,
)
from ui.viewmodels.base import ViewModel

RunnerFactory = Callable[[QObject], AsyncRunner]


class GmailViewModel(ViewModel):
    """Drives the Gmail connect / sync / disconnect / browse flows off the UI thread."""

    status_loaded = Signal(object)  # GmailStatusDTO
    connect_finished = Signal(object)  # GmailStatusDTO
    disconnect_finished = Signal(object)  # GmailStatusDTO
    sync_finished = Signal(object)  # GmailSyncDTO
    messages_loaded = Signal(object)  # tuple[GmailMessageDTO, ...]
    message_loaded = Signal(object)  # GmailMessageDetailDTO
    busy_changed = Signal(bool)

    def __init__(
        self,
        client: BackendClient,
        *,
        runner_factory: RunnerFactory = AsyncRunner,
    ) -> None:
        """Initialize the view-model.

        Args:
            client: Backend gateway for Gmail requests.
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

    def refresh_status(self) -> None:
        """Load the current connection status."""
        if self._busy:
            return
        self._pending = "status"
        self._set_busy(True)
        self._runner.run(self._client.gmail_status)

    def connect_account(self) -> None:
        """Start the OAuth connect flow (opens the system browser)."""
        if self._busy:
            return
        self._pending = "connect"
        self._set_busy(True)
        self._runner.run(self._client.gmail_connect)

    def disconnect_account(self) -> None:
        """Disconnect the Gmail account."""
        if self._busy:
            return
        self._pending = "disconnect"
        self._set_busy(True)
        self._runner.run(self._client.gmail_disconnect)

    def sync(self) -> None:
        """Trigger a synchronization pass."""
        if self._busy:
            return
        self._pending = "sync"
        self._set_busy(True)
        self._runner.run(self._client.gmail_sync)

    def load_messages(self, *, risk_filter: str = "all", search: str = "") -> None:
        """Load the analyst message list for the active account."""
        if self._busy:
            return
        self._pending = "messages"
        self._set_busy(True)
        self._runner.run(
            lambda: self._client.gmail_messages(risk_filter=risk_filter, search=search)
        )

    def open_message(self, message_id: str) -> None:
        """Load the full detail for one message."""
        if self._busy:
            return
        self._pending = "detail"
        self._set_busy(True)
        self._runner.run(lambda: self._client.gmail_message_detail(message_id))

    # --- internals -------------------------------------------------------

    def _on_result(self, result: object) -> None:
        pending, self._pending = self._pending, ""
        self._set_busy(False)
        if pending == "status" and isinstance(result, GmailStatusDTO):
            self.status_loaded.emit(result)
        elif pending == "connect" and isinstance(result, GmailStatusDTO):
            self.connect_finished.emit(result)
        elif pending == "disconnect" and isinstance(result, GmailStatusDTO):
            self.disconnect_finished.emit(result)
        elif pending == "sync" and isinstance(result, GmailSyncDTO):
            self.sync_finished.emit(result)
        elif pending == "messages" and isinstance(result, tuple):
            self.messages_loaded.emit(result)
        elif pending == "detail" and isinstance(result, GmailMessageDetailDTO):
            self.message_loaded.emit(result)

    def _set_busy(self, busy: bool) -> None:
        if busy != self._busy:
            self._busy = busy
            self.busy_changed.emit(busy)

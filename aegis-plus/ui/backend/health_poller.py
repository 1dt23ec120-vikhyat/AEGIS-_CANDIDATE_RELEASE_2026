"""Backend health poller.

Periodically checks backend liveness on a worker thread and emits a signal on
the UI thread, so the status indicator stays current without ever blocking the
interface.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal

from ui.backend.client import BackendClient, HealthResult

_DEFAULT_INTERVAL_MS = 5000


class _HealthTask(QRunnable):
    """Runs a single liveness check on a worker thread."""

    def __init__(self, poller: BackendHealthPoller, client: BackendClient) -> None:
        super().__init__()
        self._poller = poller
        self._client = client

    def run(self) -> None:
        """Execute the check and report back to the poller."""
        result = self._client.liveness()
        self._poller.report(result)


class BackendHealthPoller(QObject):
    """Emits backend connectivity status on a timer."""

    status_changed = Signal(bool, str)  # (ok, detail)

    def __init__(
        self,
        client: BackendClient,
        *,
        interval_ms: int = _DEFAULT_INTERVAL_MS,
        parent: QObject | None = None,
    ) -> None:
        """Initialize the poller.

        Args:
            client: The backend client to probe with.
            interval_ms: Poll interval in milliseconds.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._client = client
        self._pool = QThreadPool.globalInstance()
        self._active = False
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._check)

    def start(self) -> None:
        """Run an immediate check and begin polling."""
        self._active = True
        self._check()
        self._timer.start()

    def stop(self) -> None:
        """Stop polling and ignore any in-flight worker result.

        Waits briefly for an in-flight liveness task to finish so it cannot emit
        after this object begins tearing down.
        """
        self._active = False
        self._timer.stop()
        self._pool.waitForDone(1000)

    def report(self, result: HealthResult) -> None:
        """Emit a status update (called from the worker thread).

        Ignored once the poller has been stopped, so a worker task that completes
        after teardown cannot emit on a signal source that is being destroyed.
        """
        if not self._active:
            return
        self.status_changed.emit(result.ok, result.detail)

    def _check(self) -> None:
        if not self._active:
            return
        self._pool.start(_HealthTask(self, self._client))

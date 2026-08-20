"""URL scanner view-model."""

from __future__ import annotations

from PySide6.QtCore import Signal

from ui.backend import AsyncRunner, BackendClient, ScanResult
from ui.viewmodels.base import ViewModel


class UrlScannerViewModel(ViewModel):
    """Drives URL scanning: submits requests and reports results."""

    scan_started = Signal()
    scan_completed = Signal(object)  # ScanResult

    def __init__(self, client: BackendClient) -> None:
        """Initialize the view-model.

        Args:
            client: The backend client used to submit scans.
        """
        super().__init__()
        self._client = client
        self._runner = AsyncRunner(self)
        self._runner.finished.connect(self._on_finished)

    def analyze(self, raw_url: str) -> None:
        """Submit a URL for analysis (no-op for blank input)."""
        url = raw_url.strip()
        if not url:
            return
        self.scan_started.emit()
        self._runner.run(lambda: self._client.scan_url(url))

    def _on_finished(self, result: ScanResult) -> None:
        self.scan_completed.emit(result)

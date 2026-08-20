"""Copilot streaming worker (M12 Phase 3).

A lifecycle-safe worker that consumes the backend Copilot stream off the UI
thread and delivers events to the view-model via signals. Qt lifecycle safety is
the priority here (see the Phase 2 auto-scroll incident):

- The worker runs on a ``QThread`` it owns and is explicitly stopped and joined
  by :meth:`stop`, so no worker survives the page or the ``QApplication``.
- A cooperative cancellation flag lets an in-flight stream end promptly when the
  analyst clears the conversation, regenerates, or the page is destroyed.
- Emitted signals are dropped after cancellation, so a late chunk cannot mutate a
  torn-down view.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator

from PySide6.QtCore import QObject, QThread, Signal

from core.domain.copilot import CopilotStreamEvent

EventSource = Callable[[], Iterator[CopilotStreamEvent]]


class StreamWorker(QObject):
    """Consumes a Copilot event stream on a dedicated, stoppable thread."""

    token = Signal(str)
    finished = Signal(object)  # CopilotStreamEvent (kind "final" or "error")

    def __init__(self, source: EventSource, parent: QObject | None = None) -> None:
        """Initialize the worker.

        Args:
            source: A zero-arg callable returning the event iterator (the backend
                stream). It is invoked on the worker thread.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._source = source
        self._cancelled = threading.Event()
        self._thread = QThread()
        self.moveToThread(self._thread)
        self._thread.started.connect(self._run)

    def start(self) -> None:
        """Start consuming the stream on the worker thread."""
        self._thread.start()

    def cancel(self) -> None:
        """Request cooperative cancellation of the in-flight stream."""
        self._cancelled.set()

    def stop(self) -> None:
        """Cancel, quit, and join the worker thread (safe to call repeatedly)."""
        self._cancelled.set()
        if self._thread.isRunning():
            self._thread.quit()
            self._thread.wait()

    @property
    def is_cancelled(self) -> bool:
        """Whether cancellation has been requested."""
        return self._cancelled.is_set()

    def _run(self) -> None:
        final: CopilotStreamEvent | None = None
        try:
            for event in self._source():
                if self._cancelled.is_set():
                    break
                if event.kind == "token":
                    self.token.emit(event.text)
                else:
                    final = event
                    break
        except Exception as exc:
            final = CopilotStreamEvent(kind="error", error=str(exc))
        finally:
            if not self._cancelled.is_set():
                self.finished.emit(final)
            self._thread.quit()

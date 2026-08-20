"""Async runner.

Runs a callable on a worker thread and delivers its result on the UI thread via
a signal, so backend calls never block the interface.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], Any], on_done: Callable[[Any], None]) -> None:
        super().__init__()
        self._fn = fn
        self._on_done = on_done

    def run(self) -> None:
        result = self._fn()
        # The receiver (a UI object) may be torn down before the result
        # arrives; there is then nothing left to deliver to.
        with suppress(RuntimeError):
            self._on_done(result)


class AsyncRunner(QObject):
    """Runs callables off the UI thread and emits their results."""

    finished = Signal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        """Initialize the runner."""
        super().__init__(parent)
        self._pool = QThreadPool.globalInstance()

    def run(self, fn: Callable[[], Any]) -> None:
        """Execute ``fn`` on a worker thread; emit :attr:`finished` with its result."""
        self._pool.start(_Task(fn, self._emit))

    def _emit(self, result: Any) -> None:
        self.finished.emit(result)

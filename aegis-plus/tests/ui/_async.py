"""Shared UI-test helpers: a synchronous runner and an event-loop pump."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QEventLoop
from PySide6.QtWidgets import QApplication

from ui.backend import AsyncRunner


class SyncRunner(AsyncRunner):
    """An :class:`AsyncRunner` that executes work inline on the calling thread.

    Injected into view-models under test so backend calls run deterministically
    without spawning worker threads (which otherwise crash the native Qt layer
    when many are torn down across a large test session).
    """

    def run(self, fn: Callable[[], Any]) -> None:
        """Execute ``fn`` immediately and emit its result synchronously."""
        self.finished.emit(fn())


def pump_until(predicate: Callable[[], bool], *, timeout_ms: int = 2000) -> bool:
    """Process events until ``predicate`` is true or the timeout elapses."""
    app = QApplication.instance()
    assert app is not None
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline and not predicate():
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
        time.sleep(0.01)
    return predicate()

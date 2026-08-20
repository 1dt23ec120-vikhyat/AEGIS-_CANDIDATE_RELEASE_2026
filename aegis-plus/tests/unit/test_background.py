"""Unit tests for background service management."""

from __future__ import annotations

import pytest

from application.background import BackgroundService, BackgroundServiceManager
from infrastructure.logging import get_logger

pytestmark = pytest.mark.unit


class _RecordingService(BackgroundService):
    def __init__(self, name: str, events: list[str], *, fail_stop: bool = False) -> None:
        self._name = name
        self._events = events
        self._running = False
        self._fail_stop = fail_stop

    @property
    def name(self) -> str:
        return self._name

    def start(self) -> None:
        self._running = True
        self._events.append(f"start:{self._name}")

    def stop(self) -> None:
        if self._fail_stop:
            raise RuntimeError("stop failed")
        self._running = False
        self._events.append(f"stop:{self._name}")

    @property
    def is_running(self) -> bool:
        return self._running


def _manager() -> BackgroundServiceManager:
    return BackgroundServiceManager(get_logger("test"))


def test_services_start_in_order_and_stop_in_reverse() -> None:
    events: list[str] = []
    manager = _manager()
    manager.register(_RecordingService("a", events))
    manager.register(_RecordingService("b", events))

    manager.start_all()
    manager.stop_all()

    assert events == ["start:a", "start:b", "stop:b", "stop:a"]


def test_stop_all_is_resilient_to_failures() -> None:
    events: list[str] = []
    manager = _manager()
    manager.register(_RecordingService("a", events))
    manager.register(_RecordingService("b", events, fail_stop=True))

    manager.start_all()
    manager.stop_all()  # must not raise despite b failing

    assert "stop:a" in events  # a still stopped after b failed

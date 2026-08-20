"""Tests for payload-aware navigation (M9-P3-B)."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QStackedWidget, QWidget

from ui.context import UIContext
from ui.navigation import Route, Router

pytestmark = pytest.mark.ui


class _HookPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.received: list[object] = []

    def on_navigated(self, payload: object) -> None:
        self.received.append(payload)


def test_navigate_without_payload_does_not_call_hook(qapp: object) -> None:
    stack = QStackedWidget()
    router = Router(stack)
    page = _HookPage()
    router.register(Route.GRAPH_EXPLORER, page)
    router.navigate(Route.GRAPH_EXPLORER)
    assert page.received == []


def test_navigate_with_payload_calls_hook(qapp: object) -> None:
    stack = QStackedWidget()
    router = Router(stack)
    page = _HookPage()
    router.register(Route.GRAPH_EXPLORER, page)
    payload = {"focus": "a"}
    router.navigate(Route.GRAPH_EXPLORER, payload)
    assert page.received == [payload]


def test_payload_delivered_even_when_already_current(qapp: object) -> None:
    stack = QStackedWidget()
    router = Router(stack)
    page = _HookPage()
    router.register(Route.GRAPH_EXPLORER, page)
    router.navigate(Route.GRAPH_EXPLORER, {"focus": "a"})
    router.navigate(Route.GRAPH_EXPLORER, {"focus": "b"})
    assert page.received == [{"focus": "a"}, {"focus": "b"}]


def test_route_changed_emitted_once_per_switch(qapp: object) -> None:
    stack = QStackedWidget()
    router = Router(stack)
    first = _HookPage()
    second = QWidget()
    router.register(Route.GRAPH_EXPLORER, first)
    router.register(Route.DASHBOARD, second)
    changes: list[object] = []
    router.route_changed.connect(changes.append)
    router.navigate(Route.GRAPH_EXPLORER, {"focus": "a"})
    router.navigate(Route.GRAPH_EXPLORER, {"focus": "b"})  # same route, no new switch
    assert changes == [Route.GRAPH_EXPLORER]


def test_uicontext_go_to_forwards_payload() -> None:
    calls: list[tuple[object, ...]] = []
    context = UIContext(
        theme_manager=None,  # type: ignore[arg-type]
        backend_client=None,  # type: ignore[arg-type]
        navigate=lambda *args: calls.append(args),
    )
    context.go_to(Route.GRAPH_EXPLORER, {"focus": "x"})
    context.go_to(Route.DASHBOARD)
    assert calls[0] == (Route.GRAPH_EXPLORER, {"focus": "x"})
    assert calls[1] == (Route.DASHBOARD,)

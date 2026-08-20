"""Tests for the navigation framework."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication, QStackedWidget, QWidget

from ui.navigation import NAVIGATION, Route, Router, Sidebar
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def test_router_navigates_and_emits(qapp: QApplication) -> None:
    stack = QStackedWidget()
    router = Router(stack)
    page_a = QWidget()
    page_b = QWidget()
    router.register(Route.DASHBOARD, page_a)
    router.register(Route.SETTINGS, page_b)

    received: list[object] = []
    router.route_changed.connect(received.append)

    router.navigate(Route.SETTINGS)
    assert router.current_route is Route.SETTINGS
    assert stack.currentWidget() is page_b
    assert received == [Route.SETTINGS]

    # Navigating to the same route again is a no-op.
    router.navigate(Route.SETTINGS)
    assert received == [Route.SETTINGS]


def test_navigation_covers_all_routes() -> None:
    assert {entry.route for entry in NAVIGATION} == set(Route)


def test_sidebar_builds_and_activates(qapp: QApplication) -> None:
    manager = ThemeManager(ThemeMode.DARK)
    sidebar = Sidebar(manager)

    selected: list[object] = []
    sidebar.route_selected.connect(selected.append)

    sidebar.set_active(Route.INCIDENTS)
    item = sidebar._items[Route.INCIDENTS]
    assert item.isChecked()

    # A theme change refreshes icons without error.
    manager.set_mode(ThemeMode.LIGHT)

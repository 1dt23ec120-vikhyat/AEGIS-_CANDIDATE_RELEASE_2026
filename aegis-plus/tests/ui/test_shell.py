"""Integration tests for the application shell."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from ui.backend import BackendClient
from ui.context import UIContext
from ui.desktop import build_main_window
from ui.navigation import NAVIGATION, Route
from ui.shell.main_window import MainWindow
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def _context() -> UIContext:
    return UIContext(
        theme_manager=ThemeManager(ThemeMode.DARK),
        backend_client=BackendClient("http://127.0.0.1:9"),
    )


def test_main_window_registers_all_pages(qapp: QApplication) -> None:
    window = MainWindow(_context())
    for entry in NAVIGATION:
        window.router.navigate(entry.route)
        assert window.router.current_route is entry.route


def test_main_window_defaults_to_dashboard(qapp: QApplication) -> None:
    window = MainWindow(_context())
    assert window.router.current_route is Route.DASHBOARD


def test_build_main_window_applies_theme(qapp: QApplication) -> None:
    theme_manager, window = build_main_window("http://127.0.0.1:9")
    assert isinstance(window, MainWindow)
    assert qapp.styleSheet() != ""
    theme_manager.toggle()  # must not raise


def test_status_bar_reflects_backend_state(qapp: QApplication) -> None:
    window = MainWindow(_context())
    window._status_bar.set_backend_status(True)
    assert "connected" in window._status_bar._backend_label.text()
    window._status_bar.set_backend_status(False)
    assert "disconnected" in window._status_bar._backend_label.text()

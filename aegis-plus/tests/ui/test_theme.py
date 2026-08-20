"""Tests for the theme system."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from ui.theme import ThemeManager, ThemeMode, build_theme
from ui.theme.stylesheet import build_stylesheet

pytestmark = pytest.mark.ui


def test_build_theme_selects_palette() -> None:
    assert build_theme(ThemeMode.DARK).is_dark is True
    assert build_theme(ThemeMode.LIGHT).is_dark is False


def test_stylesheet_includes_palette_colours() -> None:
    theme = build_theme(ThemeMode.DARK)
    qss = build_stylesheet(theme)
    assert theme.palette.primary in qss
    assert theme.palette.bg in qss
    assert "QPushButton" in qss


def test_theme_manager_toggle_switches_mode(qapp: QApplication) -> None:
    manager = ThemeManager(ThemeMode.DARK)
    manager.apply()
    assert manager.theme.is_dark

    received: list[object] = []
    manager.theme_changed.connect(received.append)
    manager.toggle()

    assert not manager.theme.is_dark
    assert len(received) == 1
    assert qapp.styleSheet() != ""


def test_set_mode_same_mode_is_noop(qapp: QApplication) -> None:
    manager = ThemeManager(ThemeMode.DARK)
    received: list[object] = []
    manager.theme_changed.connect(received.append)
    manager.set_mode(ThemeMode.DARK)
    assert received == []

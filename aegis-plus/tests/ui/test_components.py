"""Tests for the component library and icon system."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from ui.components import (
    Badge,
    Button,
    Card,
    DataTable,
    EmptyState,
    IconButton,
    MiniBarChart,
    SearchBar,
    StatCard,
    StatusDot,
)
from ui.icons import available_icons, render_icon
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def test_icons_render_at_requested_size(qapp: QApplication) -> None:
    for name in available_icons():
        pixmap = render_icon(name, size=24, color="#FFFFFF")
        assert not pixmap.isNull()
        assert pixmap.width() == 24


def test_button_variants(qapp: QApplication) -> None:
    button = Button("Scan", variant="primary")
    assert button.property("variant") == "primary"
    button.set_variant("ghost")
    assert button.property("variant") == "ghost"


def test_badge_tone(qapp: QApplication) -> None:
    badge = Badge("High", tone="danger")
    assert badge.property("badge") == "danger"


def test_datatable_populates(qapp: QApplication) -> None:
    table = DataTable(["A", "B"])
    table.set_rows([["1", "2"], ["3", "4"]])
    assert table.rowCount() == 2
    assert table.columnCount() == 2
    cell = table.item(0, 1)
    assert cell is not None
    assert cell.text() == "2"


def test_themed_components_construct(qapp: QApplication) -> None:
    manager = ThemeManager(ThemeMode.DARK)
    stat = StatCard(manager, metric="Scans", value="10", icon_name="globe", tone="info")
    chart = MiniBarChart(manager, values=[1, 2, 3])
    assert stat is not None
    assert chart is not None

    # A theme change must not raise for theme-reactive components.
    manager.set_mode(ThemeMode.LIGHT)


def test_misc_components_construct(qapp: QApplication) -> None:
    assert Card() is not None
    assert IconButton("bell", color="#FFFFFF") is not None
    assert SearchBar("Search…") is not None
    assert StatusDot(color="#2FBF71") is not None
    assert EmptyState(icon_name="globe", title="Nothing", subtitle="yet") is not None

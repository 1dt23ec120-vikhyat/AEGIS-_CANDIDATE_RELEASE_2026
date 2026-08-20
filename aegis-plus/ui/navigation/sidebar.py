"""Sidebar navigation rail."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ui.components.text import label
from ui.icons import icon as build_icon
from ui.icons import render_icon
from ui.navigation.routes import NAVIGATION, NavEntry, Route
from ui.theme import ThemeManager

_SIDEBAR_WIDTH = 248


class _NavItem(QPushButton):
    """A single sidebar navigation button with a theme-aware icon."""

    def __init__(self, entry: NavEntry, theme_manager: ThemeManager) -> None:
        super().__init__(entry.label)
        self.entry = entry
        self._theme_manager = theme_manager
        self.setObjectName("NavItem")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setIconSize(QSize(18, 18))
        self.toggled.connect(self.refresh_icon)
        self.refresh_icon()

    def refresh_icon(self) -> None:
        """Re-tint the icon based on active state and theme."""
        palette = self._theme_manager.theme.palette
        color = palette.primary if self.isChecked() else palette.text_muted
        self.setIcon(build_icon(self.entry.icon, size=18, color=color))


class Sidebar(QWidget):
    """Brand + grouped, exclusive navigation items."""

    route_selected = Signal(object)  # emits Route

    def __init__(self, theme_manager: ThemeManager, *, parent: QWidget | None = None) -> None:
        """Initialize the sidebar.

        Args:
            theme_manager: Theme source for icon tinting and refresh.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._theme_manager = theme_manager
        self.setObjectName("Sidebar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedWidth(_SIDEBAR_WIDTH)

        column = QVBoxLayout(self)
        column.setContentsMargins(16, 20, 16, 16)
        column.setSpacing(4)

        column.addWidget(self._build_brand())
        column.addSpacing(18)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._items: dict[Route, _NavItem] = {}

        current_section = ""
        for entry in NAVIGATION:
            if entry.section != current_section:
                if current_section:
                    column.addSpacing(12)
                section = label(entry.section.upper(), role="caption")
                section.setObjectName("NavSectionLabel")
                column.addWidget(section)
                column.addSpacing(2)
                current_section = entry.section
            item = _NavItem(entry, theme_manager)
            item.clicked.connect(lambda _=False, r=entry.route: self.route_selected.emit(r))
            self._group.addButton(item)
            self._items[entry.route] = item
            column.addWidget(item)

        column.addStretch(1)
        column.addWidget(self._build_footer())

        theme_manager.theme_changed.connect(self._on_theme_changed)

    def set_active(self, route: Route) -> None:
        """Mark ``route`` as the active item without re-emitting selection."""
        item = self._items.get(route)
        if item is not None and not item.isChecked():
            item.setChecked(True)

    def _build_brand(self) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(6, 0, 0, 0)
        layout.setSpacing(10)

        self._brand_mark = QLabel()
        self._brand_mark.setObjectName("BrandMark")
        self._brand_mark.setFixedSize(34, 34)
        self._brand_mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._brand_mark.setPixmap(
            render_icon("shield", size=20, color=self._theme_manager.theme.palette.primary)
        )
        layout.addWidget(self._brand_mark)

        name = QLabel("AEGIS+")
        name.setObjectName("BrandName")
        layout.addWidget(name)
        layout.addStretch(1)
        return row

    def _build_footer(self) -> QWidget:
        footer = label("v0.1.0  ·  Platform", role="subtle")
        footer.setContentsMargins(8, 0, 0, 0)
        return footer

    def _on_theme_changed(self) -> None:
        self._brand_mark.setPixmap(
            render_icon("shield", size=20, color=self._theme_manager.theme.palette.primary)
        )
        for item in self._items.values():
            item.refresh_icon()

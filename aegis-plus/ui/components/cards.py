"""Card components."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ui.components.badges import Badge
from ui.components.text import label
from ui.icons import render_icon
from ui.theme import ThemeManager

_TONE_COLORS = {
    "primary": ("primary", "primary_soft"),
    "info": ("info", "info_soft"),
    "success": ("success", "success_soft"),
    "warning": ("warning", "warning_soft"),
    "danger": ("danger", "danger_soft"),
}


class Card(QFrame):
    """A surface panel with a subtle border and elevation."""

    def __init__(self, *, flat: bool = False, parent: QWidget | None = None) -> None:
        """Initialize the card.

        Args:
            flat: Use the flat (borderless, tinted) style.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self.setObjectName("CardFlat" if flat else "Card")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)
        self._layout = layout
        if not flat:
            shadow = QGraphicsDropShadowEffect(self)
            shadow.setBlurRadius(24)
            shadow.setOffset(0, 6)
            shadow.setColor(QColor(0, 0, 0, 40))
            self.setGraphicsEffect(shadow)

    @property
    def content_layout(self) -> QVBoxLayout:
        """The card's content layout."""
        return self._layout

    def add(self, widget: QWidget) -> None:
        """Add a widget to the card body."""
        self._layout.addWidget(widget)


class StatCard(Card):
    """A metric card: icon, value, label, and an optional trend badge."""

    def __init__(
        self,
        theme_manager: ThemeManager,
        *,
        metric: str,
        value: str,
        icon_name: str,
        tone: str = "primary",
        trend: str = "",
        trend_tone: str = "success",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the stat card.

        Args:
            theme_manager: Theme source, for accent colours and refresh.
            metric: The metric's name.
            value: The metric's current value (pre-formatted).
            icon_name: Registered icon name.
            tone: Accent tone (keys of the theme's semantic colours).
            trend: Optional trend text (e.g. ``"+12%"``).
            trend_tone: Badge tone for the trend.
            parent: Optional Qt parent.
        """
        super().__init__(parent=parent)
        self._theme_manager = theme_manager
        self._icon_name = icon_name
        self._tone = tone

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        self._chip = QLabel()
        self._chip.setFixedSize(40, 40)
        self._chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(self._chip)
        header.addStretch(1)
        if trend:
            header.addWidget(Badge(trend, tone=trend_tone))
        self.add_layout(header)

        self._value = label(value, role="display")
        self.add(self._value)
        self.add(label(metric, role="muted"))

        self._apply_theme()
        theme_manager.theme_changed.connect(self._apply_theme)

    def add_layout(self, layout: QHBoxLayout) -> None:
        """Add a sub-layout to the card body."""
        self.content_layout.addLayout(layout)

    def _apply_theme(self) -> None:
        palette = self._theme_manager.theme.palette
        color_attr, soft_attr = _TONE_COLORS.get(self._tone, _TONE_COLORS["primary"])
        color = getattr(palette, color_attr)
        soft = getattr(palette, soft_attr)
        self._chip.setStyleSheet(f"background: {soft}; border-radius: 10px;")
        self._chip.setPixmap(render_icon(self._icon_name, size=20, color=color))

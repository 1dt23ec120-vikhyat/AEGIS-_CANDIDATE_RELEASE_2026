"""Settings page."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QWidget

from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.text import SectionTitle, label
from ui.context import UIContext
from ui.pages.base_page import BasePage
from ui.theme import ThemeMode

_ABOUT = [
    ("Version", "0.1.0"),
    ("Build", "M1b · WP7"),
    ("Edition", "Enterprise Platform"),
    ("License", "Proprietary"),
]


class SettingsPage(BasePage):
    """Application preferences and information."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the settings page."""
        super().__init__(
            "Settings",
            "Configure appearance and review application information",
            parent=parent,
        )
        self._theme_manager = context.theme_manager
        self.add(self._appearance_card())
        self.add(self._about_card())
        self.add_stretch()

    def _appearance_card(self) -> Card:
        card = Card()
        card.add(SectionTitle("Appearance"))
        card.add(label("Choose the interface theme", role="muted"))

        row = QHBoxLayout()
        row.setSpacing(12)
        light = Button("Light", variant="secondary")
        dark = Button("Dark", variant="secondary")
        light.clicked.connect(lambda: self._theme_manager.set_mode(ThemeMode.LIGHT))
        dark.clicked.connect(lambda: self._theme_manager.set_mode(ThemeMode.DARK))
        row.addWidget(light)
        row.addWidget(dark)
        row.addStretch(1)
        card.content_layout.addLayout(row)
        return card

    def _about_card(self) -> Card:
        card = Card()
        card.add(SectionTitle("About AEGIS+"))
        for name, value in _ABOUT:
            row = QHBoxLayout()
            row.addWidget(label(name, role="muted"))
            row.addStretch(1)
            row.addWidget(label(value))
            card.content_layout.addLayout(row)
        return card

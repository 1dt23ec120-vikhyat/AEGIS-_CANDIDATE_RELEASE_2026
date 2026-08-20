"""Shared scaffold for the scanner pages (URL / Email / File)."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QWidget

from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.empty_state import EmptyState
from ui.components.text import SectionTitle, label
from ui.context import UIContext
from ui.pages.base_page import BasePage


class ScannerPage(BasePage):
    """A scan console with an input field and an (empty) results area."""

    def __init__(
        self,
        context: UIContext,
        *,
        title: str,
        subtitle: str,
        console_title: str,
        placeholder: str,
        action_label: str,
        empty_icon: str,
        empty_title: str,
        empty_subtitle: str,
        parent: QWidget | None = None,
    ) -> None:
        """Build a scanner page.

        Args:
            context: Shared UI dependencies.
            title: Page title.
            subtitle: Page subtitle.
            console_title: Heading for the input card.
            placeholder: Input placeholder text.
            action_label: Primary action button label.
            empty_icon: Icon for the empty results state.
            empty_title: Title for the empty results state.
            empty_subtitle: Subtitle for the empty results state.
            parent: Optional Qt parent.
        """
        super().__init__(title, subtitle, parent=parent)

        console = Card()
        console.add(SectionTitle(console_title))
        row = QHBoxLayout()
        row.setSpacing(12)
        self._input = QLineEdit()
        self._input.setPlaceholderText(placeholder)
        row.addWidget(self._input, 1)
        row.addWidget(Button(action_label, variant="primary"))
        console.content_layout.addLayout(row)
        self.add(console)

        results = Card()
        results.add(SectionTitle("Results"))
        results.add(label("Analysis output will appear here", role="muted"))
        results.add(
            EmptyState(
                icon_name=empty_icon,
                title=empty_title,
                subtitle=empty_subtitle,
            )
        )
        self.add(results)
        self.add_stretch()

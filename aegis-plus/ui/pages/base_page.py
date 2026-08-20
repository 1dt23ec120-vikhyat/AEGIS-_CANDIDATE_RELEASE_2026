"""Base page.

Common scaffold for all pages: a consistent header (title/subtitle plus optional
actions) and a spaced content column. Pages subclass this and populate the body,
giving every screen the same rhythm and margins.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget

from ui.components.text import PageHeader


class BasePage(QWidget):
    """Base class for workspace pages."""

    def __init__(self, title: str, subtitle: str = "", *, parent: QWidget | None = None) -> None:
        """Initialize the page scaffold.

        Args:
            title: Page title shown in the header.
            subtitle: Optional supporting text.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._column = QVBoxLayout(self)
        self._column.setContentsMargins(28, 24, 28, 28)
        self._column.setSpacing(20)
        self._header = PageHeader(title, subtitle)
        self._column.addWidget(self._header)

    @property
    def header(self) -> PageHeader:
        """The page header (to attach actions)."""
        return self._header

    def add(self, widget: QWidget) -> None:
        """Append a widget to the content column."""
        self._column.addWidget(widget)

    def add_layout(self, layout: QHBoxLayout | QVBoxLayout) -> None:
        """Append a sub-layout to the content column."""
        self._column.addLayout(layout)

    def add_stretch(self) -> None:
        """Add a trailing stretch so content aligns to the top."""
        self._column.addStretch(1)

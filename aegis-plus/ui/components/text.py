"""Text and header components."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget


def label(text: str, *, role: str = "body", parent: QWidget | None = None) -> QLabel:
    """Create a QLabel carrying a style ``role``.

    Args:
        text: Label text.
        role: Style role (``display``, ``h1``, ``h2``, ``h3``, ``muted``,
            ``subtle``, ``caption``, ``body``).
        parent: Optional Qt parent.

    Returns:
        The configured label.
    """
    widget = QLabel(text, parent)
    if role != "body":
        widget.setProperty("role", role)
    return widget


class SectionTitle(QWidget):
    """A small heading with an optional trailing action area."""

    def __init__(self, text: str, *, parent: QWidget | None = None) -> None:
        """Initialize the section title.

        Args:
            text: Heading text.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(label(text, role="h2"))
        row.addStretch(1)
        self._row = row

    def add_action(self, widget: QWidget) -> None:
        """Add a trailing action widget (right-aligned)."""
        self._row.addWidget(widget)


class PageHeader(QWidget):
    """A page title with subtitle and an optional actions row."""

    def __init__(self, title: str, subtitle: str = "", *, parent: QWidget | None = None) -> None:
        """Initialize the page header.

        Args:
            title: Page title.
            subtitle: Optional supporting text.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(16)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        text_col.addWidget(label(title, role="display"))
        if subtitle:
            text_col.addWidget(label(subtitle, role="muted"))
        row.addLayout(text_col)
        row.addStretch(1)
        self._row = row

    def add_action(self, widget: QWidget) -> None:
        """Add a trailing action widget (right-aligned)."""
        self._row.addWidget(widget)

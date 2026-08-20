"""Collapsible section component.

An expandable panel with a header row (title, optional status badge) and a body
that can be collapsed. Used to compose the investigation workspace, where an
analyst scans section headers first and expands only what they need.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget

from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.text import label


class Section(Card):
    """A collapsible titled panel."""

    def __init__(
        self,
        title: str,
        *,
        badge: str = "",
        badge_tone: str = "neutral",
        expanded: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        """Build a collapsible section.

        Args:
            title: The section heading.
            badge: Optional status badge text.
            badge_tone: Badge tone when ``badge`` is set.
            expanded: Whether the body starts visible.
            parent: Optional parent widget.
        """
        super().__init__(parent=parent)
        header = QHBoxLayout()
        header.addWidget(label(title, role="h2"))
        if badge:
            header.addSpacing(8)
            header.addWidget(Badge(badge, tone=badge_tone))
        header.addStretch(1)
        self._toggle = Button("Hide" if expanded else "Show", variant="secondary")
        self._toggle.clicked.connect(self._on_toggle)
        header.addWidget(self._toggle)
        self.content_layout.addLayout(header)

        self._body = QWidget()
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(0, 8, 0, 0)
        self._body_layout.setSpacing(10)
        self.content_layout.addWidget(self._body)
        self._body.setVisible(expanded)

    @property
    def body_layout(self) -> QVBoxLayout:
        """The layout that section content should be added to."""
        return self._body_layout

    def add_body(self, widget: QWidget) -> None:
        """Add a widget to the section body."""
        self._body_layout.addWidget(widget)

    def is_expanded(self) -> bool:
        """Whether the section body is currently visible."""
        return not self._body.isHidden()

    def set_expanded(self, expanded: bool) -> None:
        """Show or hide the section body."""
        self._body.setVisible(expanded)
        self._toggle.setText("Hide" if expanded else "Show")

    def _on_toggle(self) -> None:
        self.set_expanded(self._body.isHidden())

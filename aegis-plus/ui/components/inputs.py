"""Input components."""

from __future__ import annotations

from PySide6.QtWidgets import QLineEdit, QWidget

from ui.icons import icon as make_icon


class SearchBar(QLineEdit):
    """A search field with a leading search icon."""

    def __init__(
        self,
        placeholder: str = "Search…",
        *,
        icon_color: str = "#94A0B6",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the search bar.

        Args:
            placeholder: Placeholder text.
            icon_color: Colour of the leading search icon.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self.setObjectName("SearchBar")
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        self._action = self.addAction(
            make_icon("search", size=16, color=icon_color),
            QLineEdit.ActionPosition.LeadingPosition,
        )

    def set_icon_color(self, color: str) -> None:
        """Recolour the leading icon (e.g. on theme change)."""
        self._action.setIcon(make_icon("search", size=16, color=color))

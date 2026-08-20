"""Button components."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QPushButton, QWidget

from ui.icons import icon as make_icon


class Button(QPushButton):
    """A themed button with primary/secondary/ghost variants."""

    def __init__(
        self, text: str = "", *, variant: str = "primary", parent: QWidget | None = None
    ) -> None:
        """Initialize the button.

        Args:
            text: Button label.
            variant: One of ``primary``, ``secondary``, ``ghost``.
            parent: Optional Qt parent.
        """
        super().__init__(text, parent)
        self.setProperty("variant", variant)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_variant(self, variant: str) -> None:
        """Change the button variant and restyle."""
        self.setProperty("variant", variant)
        style = self.style()
        style.unpolish(self)
        style.polish(self)


class IconButton(QPushButton):
    """A borderless square button showing a single tinted icon."""

    def __init__(
        self,
        icon_name: str,
        *,
        color: str = "#FFFFFF",
        size: int = 20,
        tooltip: str = "",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the icon button.

        Args:
            icon_name: Registered icon name.
            color: Icon colour.
            size: Icon size in pixels.
            tooltip: Optional tooltip text.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self.setObjectName("IconButton")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._icon_name = icon_name
        self._icon_size = size
        self._color = color
        if tooltip:
            self.setToolTip(tooltip)
        self.set_color(color)

    def set_color(self, color: str) -> None:
        """Re-render the icon in ``color`` (e.g. on theme change)."""
        self._color = color
        self.setIcon(make_icon(self._icon_name, size=self._icon_size, color=color))
        self.setIconSize(QSize(self._icon_size, self._icon_size))

    def set_icon_name(self, name: str) -> None:
        """Swap the icon glyph, keeping the current colour."""
        self._icon_name = name
        self.set_color(self._color)

"""Empty-state component."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from ui.components.text import label
from ui.icons import render_icon


class EmptyState(QWidget):
    """A centered placeholder shown when a view has no content yet."""

    def __init__(
        self,
        *,
        icon_name: str,
        title: str,
        subtitle: str = "",
        icon_color: str = "#5F6B82",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the empty state.

        Args:
            icon_name: Registered icon name.
            title: Primary message.
            subtitle: Optional supporting message.
            icon_color: Icon colour.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.setSpacing(8)

        glyph = QLabel()
        glyph.setPixmap(render_icon(icon_name, size=44, color=icon_color))
        glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.addWidget(glyph)

        title_label = label(title, role="h3")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.addWidget(title_label)

        if subtitle:
            subtitle_label = label(subtitle, role="muted")
            subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            column.addWidget(subtitle_label)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        """Suggest a comfortable default size."""
        return QSize(320, 220)

"""Badge and status-indicator components."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPaintEvent
from PySide6.QtWidgets import QLabel, QWidget


class Badge(QLabel):
    """A pill-shaped status/severity badge styled by tone."""

    def __init__(self, text: str, *, tone: str = "neutral", parent: QWidget | None = None) -> None:
        """Initialize the badge.

        Args:
            text: Badge text.
            tone: One of ``neutral``, ``success``, ``warning``, ``danger``, ``info``.
            parent: Optional Qt parent.
        """
        super().__init__(text, parent)
        self.setProperty("badge", tone)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def set_tone(self, tone: str) -> None:
        """Change the badge tone and restyle."""
        self.setProperty("badge", tone)
        style = self.style()
        style.unpolish(self)
        style.polish(self)


class StatusDot(QWidget):
    """A small filled circle indicating a status colour."""

    def __init__(
        self, *, color: str = "#2FBF71", diameter: int = 10, parent: QWidget | None = None
    ) -> None:
        """Initialize the dot.

        Args:
            color: Fill colour.
            diameter: Diameter in pixels.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._color = color
        self._diameter = diameter
        self.setFixedSize(diameter, diameter)

    def set_color(self, color: str) -> None:
        """Change the dot colour and repaint."""
        self._color = color
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802 - Qt override
        """Paint the filled circle."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self._color))
        radius = self._diameter / 2
        painter.drawEllipse(QPointF(radius, radius), radius, radius)
        painter.end()

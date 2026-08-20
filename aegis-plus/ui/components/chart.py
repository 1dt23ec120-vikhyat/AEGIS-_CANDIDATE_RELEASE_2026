"""Lightweight chart components."""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter, QPaintEvent
from PySide6.QtWidgets import QWidget

from ui.theme import ThemeManager


class MiniBarChart(QWidget):
    """A compact bar chart painted from a series of values."""

    def __init__(
        self,
        theme_manager: ThemeManager,
        *,
        values: Sequence[float] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the chart.

        Args:
            theme_manager: Theme source for colours and refresh.
            values: The series to plot. May be set later via :meth:`set_values`.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._theme_manager = theme_manager
        self._values: list[float] = list(values or [])
        self.setMinimumHeight(160)
        theme_manager.theme_changed.connect(self.update)

    def set_values(self, values: Sequence[float]) -> None:
        """Replace the plotted series and repaint."""
        self._values = list(values)
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        """Suggest a default size."""
        return QSize(480, 180)

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802 - Qt override
        """Paint the bars."""
        if not self._values:
            return
        palette = self._theme_manager.theme.palette
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        width = self.width()
        height = self.height()
        peak = max(self._values) or 1.0
        count = len(self._values)
        gap = 10.0
        bar_width = max(4.0, (width - gap * (count - 1)) / count)

        base_color = QColor(palette.primary)
        soft_color = QColor(palette.primary)
        soft_color.setAlpha(46)

        for index, value in enumerate(self._values):
            bar_height = (value / peak) * (height - 12)
            x = index * (bar_width + gap)
            track = QRectF(x, 0, bar_width, height)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(soft_color)
            painter.drawRoundedRect(track, 4, 4)
            bar = QRectF(x, height - bar_height, bar_width, bar_height)
            painter.setBrush(base_color)
            painter.drawRoundedRect(bar, 4, 4)
        painter.end()

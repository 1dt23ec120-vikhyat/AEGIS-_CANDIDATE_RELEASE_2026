"""Splash screen.

A branded splash shown while the application initializes. The pixmap is painted
from the dark palette so it reads as part of the product before the theme is
applied to widgets.
"""

from __future__ import annotations

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap
from PySide6.QtWidgets import QSplashScreen

from ui.icons import render_icon
from ui.theme.tokens import DARK

_WIDTH = 460
_HEIGHT = 280


class SplashScreen(QSplashScreen):
    """The startup splash screen."""

    def __init__(self) -> None:
        """Build and show the splash pixmap."""
        super().__init__(self._render())
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)

    @staticmethod
    def _render() -> QPixmap:
        pixmap = QPixmap(_WIDTH, _HEIGHT)
        pixmap.fill(QColor(DARK.bg))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        painter.setPen(QColor(DARK.border))
        painter.drawRoundedRect(QRect(1, 1, _WIDTH - 2, _HEIGHT - 2), 14, 14)

        mark = render_icon("shield", size=64, color=DARK.primary)
        painter.drawPixmap((_WIDTH - 64) // 2, 66, mark)

        painter.setPen(QColor(DARK.text))
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(QRect(0, 150, _WIDTH, 40), Qt.AlignmentFlag.AlignCenter, "AEGIS+")

        painter.setPen(QColor(DARK.text_muted))
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        painter.setFont(subtitle_font)
        painter.drawText(
            QRect(0, 192, _WIDTH, 24),
            Qt.AlignmentFlag.AlignCenter,
            "AI-Powered Phishing & Identity Attack Detection",
        )

        painter.setPen(QColor(DARK.text_subtle))
        painter.drawText(
            QRect(0, 236, _WIDTH, 20),
            Qt.AlignmentFlag.AlignCenter,
            "Initializing platform…",
        )
        painter.end()
        return pixmap

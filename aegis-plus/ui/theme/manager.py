"""Theme manager.

Holds the active theme, applies the generated stylesheet to the running
application, and switches between modes. Emits :attr:`theme_changed` so painted
widgets (icons, charts, status dots) that cannot be styled by QSS can refresh.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

from ui.theme.stylesheet import build_stylesheet
from ui.theme.theme import Theme, ThemeMode, build_theme


class ThemeManager(QObject):
    """Owns and applies the active theme."""

    theme_changed = Signal(object)  # emits the new Theme

    def __init__(self, mode: ThemeMode = ThemeMode.DARK) -> None:
        """Initialize with a starting mode.

        Args:
            mode: The initial theme mode.
        """
        super().__init__()
        self._theme = build_theme(mode)

    @property
    def theme(self) -> Theme:
        """The active theme."""
        return self._theme

    def apply(self) -> None:
        """Apply the active theme's stylesheet to the application."""
        app = QApplication.instance()
        if isinstance(app, QApplication):
            app.setStyleSheet(build_stylesheet(self._theme))

    def set_mode(self, mode: ThemeMode) -> None:
        """Switch to ``mode`` and re-apply, notifying listeners.

        Args:
            mode: The theme mode to activate.
        """
        if mode is self._theme.mode:
            return
        self._theme = build_theme(mode)
        self.apply()
        self.theme_changed.emit(self._theme)

    def toggle(self) -> None:
        """Toggle between light and dark modes."""
        self.set_mode(ThemeMode.LIGHT if self._theme.is_dark else ThemeMode.DARK)

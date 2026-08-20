"""Top bar.

The workspace header: current page title, a global search field, a theme toggle,
a notifications button, and a user avatar. Icons and the avatar recolour on theme
change; the title is driven by the router.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from ui.components.buttons import IconButton
from ui.components.inputs import SearchBar
from ui.theme import ThemeManager

_HEIGHT = 64


class TopBar(QWidget):
    """The application's top toolbar."""

    logout_requested = Signal()

    def __init__(self, theme_manager: ThemeManager, *, parent: QWidget | None = None) -> None:
        """Initialize the top bar.

        Args:
            theme_manager: Theme source for icon tinting and toggling.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._theme_manager = theme_manager
        self.setObjectName("TopBar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(_HEIGHT)

        row = QHBoxLayout(self)
        row.setContentsMargins(24, 0, 20, 0)
        row.setSpacing(14)

        self._title = QLabel("Dashboard")
        self._title.setObjectName("PageTitle")
        row.addWidget(self._title)
        row.addStretch(1)

        self._search = SearchBar("Search AEGIS+…")
        self._search.setMinimumWidth(240)
        self._search.setMaximumWidth(320)
        row.addWidget(self._search)

        self._theme_button = IconButton("sun", tooltip="Toggle theme")
        self._theme_button.clicked.connect(self._theme_manager.toggle)
        row.addWidget(self._theme_button)

        self._bell = IconButton("bell", tooltip="Notifications")
        row.addWidget(self._bell)

        self._avatar = QLabel("AE")
        self._avatar.setFixedSize(34, 34)
        self._avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(self._avatar)

        self._logout = IconButton("log-out", tooltip="Sign out")
        self._logout.clicked.connect(self.logout_requested)
        row.addWidget(self._logout)

        self._apply_theme()
        theme_manager.theme_changed.connect(self._apply_theme)

    def set_title(self, title: str) -> None:
        """Set the displayed page title."""
        self._title.setText(title)

    def set_account(self, full_name: str) -> None:
        """Set the avatar initials from the authenticated user's name."""
        initials = _initials(full_name)
        if initials:
            self._avatar.setText(initials)
        self._avatar.setToolTip(full_name)

    def _apply_theme(self) -> None:
        palette = self._theme_manager.theme.palette
        muted = palette.text_muted
        self._theme_button.set_icon_name("sun" if self._theme_manager.theme.is_dark else "moon")
        self._theme_button.set_color(muted)
        self._bell.set_color(muted)
        self._logout.set_color(muted)
        self._search.set_icon_color(muted)
        self._avatar.setStyleSheet(
            f"background: {palette.primary}; color: {palette.text_on_accent};"
            f" border-radius: 17px; font-weight: 700;"
        )


def _initials(full_name: str) -> str:
    parts = [p for p in full_name.strip().split() if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()

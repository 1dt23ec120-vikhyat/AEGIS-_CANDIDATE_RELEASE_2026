"""Status bar.

The bottom bar: a live backend connection indicator, the environment, version,
and a clock. Backend status is pushed in from the health poller; the clock
updates on a timer.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTime, QTimer
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from ui.components.badges import StatusDot
from ui.components.text import label
from ui.theme import ThemeManager

_HEIGHT = 30


class StatusBar(QWidget):
    """The application's bottom status bar."""

    def __init__(
        self,
        theme_manager: ThemeManager,
        *,
        environment: str = "Local",
        version: str = "0.1.0",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the status bar.

        Args:
            theme_manager: Theme source for status colours.
            environment: Environment label to display.
            version: Version label to display.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._theme_manager = theme_manager
        self.setObjectName("StatusBar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(_HEIGHT)

        row = QHBoxLayout(self)
        row.setContentsMargins(20, 0, 20, 0)
        row.setSpacing(8)

        self._dot = StatusDot(color=self._muted_color(), diameter=9)
        row.addWidget(self._dot)
        self._backend_label = label("Backend: connecting…", role="caption")
        row.addWidget(self._backend_label)

        row.addStretch(1)
        row.addWidget(label(f"Environment: {environment}", role="caption"))
        row.addWidget(self._separator())
        row.addWidget(label(f"v{version}", role="caption"))
        row.addWidget(self._separator())

        self._clock = label("", role="caption")
        row.addWidget(self._clock)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._tick()
        self._timer.start()

    def set_backend_status(self, ok: bool, detail: str = "") -> None:
        """Update the backend connection indicator.

        Args:
            ok: Whether the backend is reachable.
            detail: Optional detail text (shown when disconnected).
        """
        palette = self._theme_manager.theme.palette
        if ok:
            self._dot.set_color(palette.success)
            self._backend_label.setText("Backend: connected")
        else:
            self._dot.set_color(palette.danger)
            self._backend_label.setText("Backend: disconnected")

    def _separator(self) -> QLabel:
        return label("·", role="subtle")

    def _tick(self) -> None:
        self._clock.setText(QTime.currentTime().toString("HH:mm:ss"))

    def _muted_color(self) -> str:
        return self._theme_manager.theme.palette.text_subtle

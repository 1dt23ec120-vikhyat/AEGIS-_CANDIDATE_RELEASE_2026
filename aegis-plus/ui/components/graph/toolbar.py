"""Graph explorer toolbar.

Viewport and query controls for the canvas: fit, zoom, reload, and an expansion
depth selector. Emits intents; the page wires them to the view-model and canvas.
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QSpinBox, QWidget

from ui.components.buttons import Button
from ui.components.text import label

_MIN_DEPTH = 1
_MAX_DEPTH = 4


class GraphToolbar(QWidget):
    """A compact toolbar over the graph canvas."""

    fit_requested = Signal()
    zoom_in_requested = Signal()
    zoom_out_requested = Signal()
    reload_requested = Signal()
    depth_changed = Signal(int)

    def __init__(self, *, parent: QWidget | None = None) -> None:
        """Build the toolbar."""
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        fit = Button("Fit", variant="secondary")
        fit.clicked.connect(self.fit_requested.emit)
        zoom_in = Button("+", variant="secondary")
        zoom_in.clicked.connect(self.zoom_in_requested.emit)
        zoom_out = Button("\u2212", variant="secondary")
        zoom_out.clicked.connect(self.zoom_out_requested.emit)
        reload_btn = Button("Reload", variant="ghost")
        reload_btn.clicked.connect(self.reload_requested.emit)

        self._depth = QSpinBox()
        self._depth.setRange(_MIN_DEPTH, _MAX_DEPTH)
        self._depth.setValue(_MIN_DEPTH)
        self._depth.valueChanged.connect(self.depth_changed.emit)

        row.addWidget(fit)
        row.addWidget(zoom_in)
        row.addWidget(zoom_out)
        row.addStretch(1)
        depth_label: QLabel = label("Expand depth", role="muted")
        row.addWidget(depth_label)
        row.addWidget(self._depth)
        row.addWidget(reload_btn)

    @property
    def current_depth(self) -> int:
        """The current expansion depth."""
        return int(self._depth.value())

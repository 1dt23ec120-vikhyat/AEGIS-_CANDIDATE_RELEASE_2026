"""AI Models page."""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QVBoxLayout, QWidget

from ui.components.badges import Badge
from ui.components.cards import Card
from ui.components.text import SectionTitle, label
from ui.context import UIContext
from ui.pages.base_page import BasePage

_MODELS = [
    ("URL Analysis Model", "Gradient-boosted classifier", "Active", "success", "98.7%", "v2.4.1"),
    ("Email Analysis Model", "Transformer (fine-tuned)", "Active", "success", "97.9%", "v1.8.0"),
    ("Screenshot Model", "Vision CNN", "Ready", "info", "96.2%", "v1.2.3"),
    ("Logo Detection Model", "Object detector", "Training", "warning", "94.5%", "v0.9.0"),
]


class AiModelsPage(BasePage):
    """Monitor the AI models powering detection."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the AI models page."""
        super().__init__(
            "AI Models",
            "Status, accuracy, and versions of the detection models",
            parent=parent,
        )
        grid = QGridLayout()
        grid.setSpacing(16)
        for index, model in enumerate(_MODELS):
            grid.addWidget(self._model_card(*model), index // 2, index % 2)
        self.add_layout_grid(grid)
        self.add_stretch()

    def add_layout_grid(self, grid: QGridLayout) -> None:
        """Add a grid layout to the content column."""
        container = QWidget()
        container.setLayout(grid)
        self.add(container)

    def _model_card(
        self,
        name: str,
        kind: str,
        status: str,
        status_tone: str,
        accuracy: str,
        version: str,
    ) -> Card:
        card = Card()

        header = QHBoxLayout()
        header.addWidget(SectionTitle(name), 1)
        header.addWidget(Badge(status, tone=status_tone))
        card.content_layout.addLayout(header)
        card.add(label(kind, role="muted"))

        metrics = QHBoxLayout()
        metrics.addLayout(self._metric("Accuracy", accuracy))
        metrics.addStretch(1)
        metrics.addLayout(self._metric("Version", version))
        card.content_layout.addLayout(metrics)
        return card

    def _metric(self, name: str, value: str) -> QVBoxLayout:
        column = QVBoxLayout()
        column.setSpacing(2)
        column.addWidget(label(value, role="h2"))
        column.addWidget(label(name, role="caption"))
        return column

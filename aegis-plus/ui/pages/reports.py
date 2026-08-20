"""Reports page."""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.tables import DataTable
from ui.components.text import SectionTitle
from ui.context import UIContext
from ui.pages.base_page import BasePage

_REPORTS = [
    ["Weekly Threat Summary", "Scheduled", "2026-07-20", "PDF"],
    ["Phishing Campaign Analysis", "On-demand", "2026-07-18", "PDF"],
    ["Model Performance Review", "Scheduled", "2026-07-15", "CSV"],
    ["Incident Response Digest", "On-demand", "2026-07-12", "PDF"],
]


class ReportsPage(BasePage):
    """Generate and browse security reports."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the reports page."""
        super().__init__(
            "Reports",
            "Generate, schedule, and export security and compliance reports",
            parent=parent,
        )
        self.header.add_action(Button("Generate Report", variant="primary"))

        card = Card()
        card.add(SectionTitle("Available Reports"))
        table = DataTable(["Report", "Type", "Last Generated", "Format"])
        table.set_rows(_REPORTS)
        table.setMinimumHeight(260)
        card.add(table)
        self.add(card)
        self.add_stretch()

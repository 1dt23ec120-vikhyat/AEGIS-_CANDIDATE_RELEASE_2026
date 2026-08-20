"""Threat Intelligence page.

Lists blacklisted URLs with search and sorting, and shows the stored analysis
(verdict, scores, indicators) for a selected entry - the "view previous
analysis" affordance. Data is loaded from the backend over HTTP.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget

from ui.backend import AsyncRunner, ThreatEntryDTO
from ui.components.badges import Badge
from ui.components.cards import Card
from ui.components.inputs import SearchBar
from ui.components.tables import DataTable
from ui.components.text import SectionTitle, label
from ui.context import UIContext
from ui.pages.base_page import BasePage

_COLUMNS = ["Artifact", "Type", "Verdict", "Risk", "First Detected", "Last Detected", "Detections"]
_VERDICT_TONE = {"legitimate": "success", "suspicious": "warning", "phishing": "danger"}


class ThreatIntelligencePage(BasePage):
    """The blacklist of detected malicious URLs."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the threat intelligence page."""
        super().__init__(
            "Threat Intelligence",
            "Blacklisted URLs blocked to protect your system",
            parent=parent,
        )
        self._entries: list[ThreatEntryDTO] = []
        self._filtered: list[ThreatEntryDTO] = []

        card = Card()
        header = QHBoxLayout()
        header.addWidget(SectionTitle("Blacklisted URLs"), 1)
        self._search = SearchBar("Search or filter…")
        self._search.setMaximumWidth(280)
        self._search.textChanged.connect(self._apply_filter)
        header.addWidget(self._search)
        card.content_layout.addLayout(header)

        self._table = DataTable(_COLUMNS)
        self._table.setSortingEnabled(True)
        self._table.setMinimumHeight(280)
        self._table.itemSelectionChanged.connect(self._on_select)
        card.add(self._table)

        self._empty = label(
            "No threats blacklisted yet — malicious URLs are added automatically.",
            role="muted",
        )
        card.add(self._empty)
        self.add(card)

        self._detail = Card()
        self._detail.add(SectionTitle("Analysis Report"))
        self._detail_body: QWidget | None = None
        self._detail.hide()
        self.add(self._detail)
        self.add_stretch()

        self._runner = AsyncRunner(self)
        self._runner.finished.connect(self._on_loaded)
        client = context.backend_client
        self._runner.run(client.list_threats)

    def _on_loaded(self, entries: list[ThreatEntryDTO]) -> None:
        self._entries = entries
        self._apply_filter(self._search.text())

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        self._filtered = [
            e
            for e in self._entries
            if not needle or needle in e.url.lower() or needle in e.verdict.lower()
        ]
        self._empty.setVisible(not self._filtered)
        self._table.setSortingEnabled(False)
        self._table.set_rows(
            [
                [
                    e.url,
                    e.artifact_type.upper(),
                    e.verdict.title(),
                    f"{e.risk_percent}%",
                    e.first_detected[:10],
                    e.last_detected[:10],
                    str(e.detection_count),
                ]
                for e in self._filtered
            ]
        )
        self._table.setSortingEnabled(True)

    def _on_select(self) -> None:
        row = self._table.currentRow()
        if row < 0 or row >= len(self._filtered):
            return
        self._show_detail(self._filtered[row])

    def _show_detail(self, entry: ThreatEntryDTO) -> None:
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(10)

        head = QHBoxLayout()
        head.addWidget(
            Badge(entry.verdict.upper(), tone=_VERDICT_TONE.get(entry.verdict, "danger"))
        )
        head.addStretch(1)
        head.addWidget(label(f"{entry.risk_percent}% risk", role="h2"))
        column.addLayout(head)
        column.addWidget(label(entry.url, role="muted"))
        column.addWidget(
            label(
                f"Detected {entry.detection_count}x  ·  "
                f"first {entry.first_detected[:10]}  ·  last {entry.last_detected[:10]}",
                role="caption",
            )
        )

        if entry.indicators:
            table = DataTable(["Indicator", "Why it matters"])
            table.set_rows(
                [[i.feature.replace("_", " ").title(), i.detail] for i in entry.indicators]
            )
            table.setMinimumHeight(160)
            column.addWidget(table)

        if self._detail_body is not None:
            self._detail.content_layout.removeWidget(self._detail_body)
            self._detail_body.deleteLater()
        self._detail_body = body
        self._detail.content_layout.addWidget(body)
        self._detail.show()

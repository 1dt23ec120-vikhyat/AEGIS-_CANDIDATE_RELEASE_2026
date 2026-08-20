"""File Scanner page — Unified Investigation Workspace.

The analyst workspace for the File Intelligence vertical, built entirely on the
reusable investigation components. An analyst selects a file, which is analyzed
statically; the workspace then presents the unified investigation layout:

    Header → Timeline → Evidence Tree → Relationships → IOC Workspace →
    Metadata → Threat History → Provider Diagnostics → Recommendations →
    Performance → Analyst Notes

The same components serve URL, email, file, and all future artifact types.
The page depends only on Core DTOs and reaches the backend over HTTP.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.domain.investigation import InvestigationSummary
from ui.backend import AsyncRunner, FileScanResult, InvestigationDTO
from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.empty_state import EmptyState
from ui.components.inputs import SearchBar
from ui.components.investigation import (
    EvidenceTreePanel,
    InvestigationHeader,
    IOCPanel,
    MetadataPanel,
    PerformancePanel,
    ProviderDiagnosticsPanel,
    RecommendationsPanel,
    RelationshipPanel,
    ThreatHistoryPanel,
    TimelinePanel,
)
from ui.components.section import Section
from ui.components.tables import DataTable
from ui.components.text import SectionTitle, label
from ui.context import UIContext
from ui.navigation import Route
from ui.pages.base_page import BasePage

_VERDICT_TONE = {"legitimate": "success", "suspicious": "warning", "phishing": "danger"}
_STATUSES = [
    ("open", "Open"),
    ("under_investigation", "Under Investigation"),
    ("confirmed_threat", "Confirmed Threat"),
    ("false_positive", "False Positive"),
    ("resolved", "Resolved"),
]
_PRIORITIES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]
_MAX_UPLOAD = 25 * 1024 * 1024
_DASH = "\u2014"


class FileScannerPage(BasePage):
    """Analyst workspace using the unified investigation components."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the investigation workspace."""
        super().__init__(
            "File Investigation",
            "Analyze files statically for macros, scripts, packing, and payloads",
            parent=parent,
        )
        self._context = context
        self._runner = AsyncRunner(self)
        self._runner.finished.connect(self._on_completed)
        self._body: QWidget | None = None
        self._result: FileScanResult | None = None
        self._selected: Path | None = None
        self._status = QComboBox()
        self._priority = QComboBox()
        self._tags = SearchBar()
        self._notes = QPlainTextEdit()

        self._graph_action = Button("Open in Graph Explorer", variant="ghost")
        self._graph_action.clicked.connect(self._open_graph)
        self._graph_action.hide()
        self.header.add_action(self._graph_action)

        self._copilot_action = Button("Ask Copilot", variant="ghost")
        self._copilot_action.clicked.connect(self._ask_copilot)
        self._copilot_action.hide()
        self.header.add_action(self._copilot_action)

        console = Card()
        console.add(SectionTitle("Submit a file"))
        console.add(
            label(
                "Select a file to analyze. It is inspected statically and never "
                "executed; its bytes are discarded after analysis and never stored.",
                role="muted",
            )
        )
        actions = QHBoxLayout()
        self._choose = Button("Choose file\u2026", variant="secondary")
        self._choose.clicked.connect(self._pick_file)
        self._button = Button("Analyze file", variant="primary")
        self._button.clicked.connect(self._submit)
        self._button.setEnabled(False)
        self._selection = label("No file selected", role="muted")
        actions.addWidget(self._choose)
        actions.addWidget(self._button)
        actions.addSpacing(12)
        actions.addWidget(self._selection)
        actions.addStretch(1)
        console.content_layout.addLayout(actions)
        self.add(console)

        self._workspace = Card()
        self.add(self._workspace)
        self.add_stretch()
        self._set_body(
            EmptyState(
                icon_name="file",
                title="No investigation open",
                subtitle="Choose a file to open an investigation workspace",
            )
        )

    def _pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to analyze")
        if not path:
            return
        self._selected = Path(path)
        self._selection.setText(self._selected.name)
        self._button.setEnabled(True)

    def _submit(self) -> None:
        if self._selected is None:
            return
        try:
            data = self._selected.read_bytes()
        except OSError as exc:
            self._set_body(label(f"Could not read the file: {exc}", role="muted"))
            return
        if len(data) > _MAX_UPLOAD:
            self._set_body(label("The file exceeds the 25 MB analysis limit.", role="muted"))
            return
        filename = self._selected.name
        self._button.setEnabled(False)
        self._set_body(label("Analyzing\u2026", role="muted"))
        client = self._context.backend_client
        self._runner.run(lambda: client.scan_file(filename, data))

    def _on_completed(self, result: object) -> None:
        if not isinstance(result, FileScanResult):
            return
        self._button.setEnabled(True)
        self._result = result
        self._graph_action.setVisible(bool(result.sha256))
        self._copilot_action.setVisible(bool(result.sha256))
        self._set_body(self._build_workspace(result))

    def _open_graph(self) -> None:
        if self._result is None or not self._result.sha256:
            return
        self._context.go_to(
            Route.GRAPH_EXPLORER,
            {"focus": self._result.sha256, "origin": Route.FILE_SCANNER},
        )

    def _ask_copilot(self) -> None:
        if self._result is None or not self._result.sha256:
            return
        self._context.go_to(
            Route.COPILOT,
            {
                "focus": self._result.sha256,
                "kind": "artifact",
                "origin": Route.FILE_SCANNER,
            },
        )

    def _save_investigation(self) -> None:
        if self._result is None or not self._result.scan_id:
            return
        tags = tuple(t.strip() for t in self._tags.text().split(",") if t.strip())
        client = self._context.backend_client
        scan_id = self._result.scan_id
        status = _STATUSES[self._status.currentIndex()][0]
        priority = _PRIORITIES[self._priority.currentIndex()][0]
        notes = self._notes.toPlainText()
        self._runner.run(
            lambda: client.save_file_investigation(
                scan_id,
                status=status,
                priority=priority,
                tags=tags,
                notes=notes,
            )
        )

    def _set_body(self, widget: QWidget) -> None:
        if self._body is not None:
            self._workspace.content_layout.removeWidget(self._body)
            self._body.deleteLater()
        self._body = widget
        self._workspace.content_layout.addWidget(widget)

    def _build_workspace(self, result: FileScanResult) -> QWidget:
        container = QWidget()
        column = QVBoxLayout(container)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(14)

        if not result.ok:
            column.addWidget(Badge("Investigation failed", tone="danger"))
            column.addWidget(label(result.error or "Unknown error", role="muted"))
            return container

        summary = self._build_summary(result)
        tm = self._context.theme_manager

        # Unified layout: Header → Timeline → Evidence Tree → Relationships →
        # IOC Workspace → Metadata → Threat History → Provider Diagnostics →
        # Recommendations → Performance → Embedded URLs → Analyst Notes
        column.addWidget(InvestigationHeader(summary))
        column.addWidget(TimelinePanel(summary.timeline))
        column.addWidget(EvidenceTreePanel(summary.evidence_tree, tm))
        column.addWidget(RelationshipPanel(summary.relationships))
        column.addWidget(IOCPanel(summary))
        column.addWidget(self._indicators_section(result))
        column.addWidget(MetadataPanel(summary.metadata))
        column.addWidget(self._urls_section(result))
        column.addWidget(
            ThreatHistoryPanel(
                summary.threat_history,
                incident_id=result.incident_id,
                incident_title=result.incident_title,
                campaign_name=result.campaign_name,
            )
        )
        column.addWidget(ProviderDiagnosticsPanel(summary.provider_diagnostics))
        column.addWidget(RecommendationsPanel(summary.recommendations, summary.technique_ids))
        column.addWidget(PerformancePanel(summary.performance))
        column.addWidget(self._notes_section(result))
        return container

    def _build_summary(self, result: FileScanResult) -> InvestigationSummary:
        """Return the unified investigation summary built by the backend.

        Construction happens server-side and arrives as a DTO, so the UI reaches
        application logic only through :class:`BackendClient` (Clean Architecture
        dependency rule). A defensive empty summary keeps the workspace rendering
        if the field is ever absent.
        """
        return result.investigation if result.investigation is not None else InvestigationSummary()

    def _indicators_section(self, result: FileScanResult) -> QWidget:
        indicators = result.indicators
        total = indicators.total if indicators else 0
        section = Section(
            "Indicators of Compromise",
            badge=f"{total} extracted",
            badge_tone="warning" if total else "success",
            expanded=bool(total),
        )
        if indicators is None or total == 0:
            section.add_body(label("No indicators of compromise were extracted.", role="muted"))
            return section
        rows: list[list[str]] = []
        rows.extend(["URL", v] for v in indicators.urls)
        rows.extend(["Domain", v] for v in indicators.domains)
        rows.extend(["IPv4", v] for v in indicators.ipv4_addresses)
        rows.extend(["Email", v] for v in indicators.emails)
        rows.extend(["Hash", v] for v in indicators.hashes)
        table = DataTable(["Type", "Indicator"])
        table.set_rows(rows)
        table.setMinimumHeight(min(360, 60 + len(rows) * 30))
        section.add_body(table)
        return section

    def _urls_section(self, result: FileScanResult) -> QWidget:
        badge = (
            f"{result.malicious_url_count} malicious"
            if result.malicious_url_count
            else f"{result.url_count} found"
        )
        section = Section(
            "Embedded URLs",
            badge=badge,
            badge_tone="danger" if result.malicious_url_count else "neutral",
            expanded=bool(result.urls),
        )
        if not result.urls:
            section.add_body(label("No embedded URLs were found.", role="muted"))
            return section
        table = DataTable(["URL", "Verdict", "Risk", "Blacklisted"])
        table.set_rows(
            [
                [u.url, u.verdict, f"{u.risk_percent}%", "Yes" if u.blacklisted else "No"]
                for u in result.urls
            ]
        )
        table.setMinimumHeight(180)
        section.add_body(table)
        return section

    def _notes_section(self, result: FileScanResult) -> QWidget:
        section = Section("Analyst Notes", expanded=False)
        investigation = InvestigationDTO(scan_id=result.scan_id)
        if result.scan_id:
            investigation = self._context.backend_client.get_file_investigation(result.scan_id)

        self._status = QComboBox()
        for _, text in _STATUSES:
            self._status.addItem(text)
        self._status.setCurrentIndex(
            next((i for i, (k, _) in enumerate(_STATUSES) if k == investigation.status), 0)
        )
        self._priority = QComboBox()
        for _, text in _PRIORITIES:
            self._priority.addItem(text)
        self._priority.setCurrentIndex(
            next((i for i, (k, _) in enumerate(_PRIORITIES) if k == investigation.priority), 1)
        )
        self._tags = SearchBar()
        self._tags.setPlaceholderText("Tags (comma separated)")
        self._tags.setText(", ".join(investigation.tags))
        self._notes = QPlainTextEdit()
        self._notes.setPlaceholderText("Investigation notes\u2026")
        self._notes.setPlainText(investigation.notes)
        self._notes.setMinimumHeight(120)

        controls = QHBoxLayout()
        controls.addWidget(label("Status", role="muted"))
        controls.addWidget(self._status)
        controls.addSpacing(12)
        controls.addWidget(label("Priority", role="muted"))
        controls.addWidget(self._priority)
        controls.addStretch(1)
        section.body_layout.addLayout(controls)
        section.add_body(self._tags)
        section.add_body(self._notes)
        save_row = QHBoxLayout()
        save = Button("Save investigation", variant="primary")
        save.clicked.connect(self._save_investigation)
        save_row.addWidget(save)
        save_row.addStretch(1)
        section.body_layout.addLayout(save_row)
        return section

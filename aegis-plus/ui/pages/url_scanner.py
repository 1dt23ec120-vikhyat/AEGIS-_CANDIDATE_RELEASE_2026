"""URL Scanner page.

Submits a URL to the backend for analysis and renders the explainable result:
verdict, threat score, confidence, and the contributing indicators. Blacklisted
URLs are flagged, and opening a URL is guarded by the threat protection service -
a blocked URL raises a warning dialog instead of launching the browser.
"""

from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QVBoxLayout, QWidget

from ui.backend import AsyncRunner, ScanResult, ThreatStatus
from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.empty_state import EmptyState
from ui.components.tables import DataTable
from ui.components.text import SectionTitle, label
from ui.components.threat_dialog import ThreatWarningDialog
from ui.context import UIContext
from ui.navigation.routes import Route
from ui.pages.base_page import BasePage
from ui.viewmodels.url_scanner import UrlScannerViewModel

_VERDICT_TONE = {"legitimate": "success", "suspicious": "warning", "phishing": "danger"}


class UrlScannerPage(BasePage):
    """Analyze URLs for phishing and identity-attack indicators."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the URL scanner page."""
        super().__init__(
            "URL Scanner",
            "Inspect links for phishing, spoofing, and malicious redirects",
            parent=parent,
        )
        self._context = context
        self._vm = UrlScannerViewModel(context.backend_client)
        self._open_runner = AsyncRunner(self)
        self._open_runner.finished.connect(self._on_guard_result)
        self._pending_open: str = ""
        self._body: QWidget | None = None
        self._result: ScanResult | None = None

        self._copilot_action = Button("Ask Copilot", variant="ghost")
        self._copilot_action.clicked.connect(self._ask_copilot)
        self._copilot_action.hide()
        self.header.add_action(self._copilot_action)

        console = Card()
        console.add(SectionTitle("Scan a URL"))
        row = QHBoxLayout()
        row.setSpacing(12)
        self._input = QLineEdit()
        self._input.setPlaceholderText("https://example.com/login")
        self._input.returnPressed.connect(self._submit)
        self._button = Button("Scan URL", variant="primary")
        self._button.clicked.connect(self._submit)
        row.addWidget(self._input, 1)
        row.addWidget(self._button)
        console.content_layout.addLayout(row)
        self.add(console)

        self._results = Card()
        self._results.add(SectionTitle("Results"))
        self.add(self._results)
        self.add_stretch()

        self._set_body(
            EmptyState(
                icon_name="globe",
                title="No URL scanned yet",
                subtitle="Enter a URL above to run a multi-layer analysis",
            )
        )

        self._vm.scan_started.connect(self._on_started)
        self._vm.scan_completed.connect(self._on_completed)

    def _submit(self) -> None:
        self._vm.analyze(self._input.text())

    def _on_started(self) -> None:
        self._button.setEnabled(False)
        self._set_body(label("Analyzing…", role="muted"))

    def _on_completed(self, result: ScanResult) -> None:
        self._button.setEnabled(True)
        self._result = result
        self._copilot_action.setVisible(result.ok and bool(result.url))
        self._set_body(self._build_result(result))

    def _ask_copilot(self) -> None:
        if self._result is None or not self._result.url:
            return
        self._context.go_to(
            Route.COPILOT,
            {"focus": self._result.url, "kind": "artifact", "origin": Route.URL_SCANNER},
        )

    def _set_body(self, widget: QWidget) -> None:
        if self._body is not None:
            self._results.content_layout.removeWidget(self._body)
            self._body.deleteLater()
        self._body = widget
        self._results.content_layout.addWidget(widget)

    def _build_result(self, result: ScanResult) -> QWidget:
        container = QWidget()
        column = QVBoxLayout(container)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(12)

        if not result.ok:
            column.addWidget(Badge("Scan failed", tone="danger"))
            column.addWidget(label(result.error or "Unknown error", role="muted"))
            return container

        blocked = result.blacklisted or result.blacklist_hit
        header = QHBoxLayout()
        if blocked:
            header.addWidget(Badge("BLACKLISTED", tone="danger"))
        else:
            header.addWidget(
                Badge(result.verdict.upper(), tone=_VERDICT_TONE.get(result.verdict, "neutral"))
            )
        header.addStretch(1)
        header.addWidget(label(f"{result.risk_percent}% risk", role="h2"))
        column.addLayout(header)

        if result.blacklist_hit:
            column.addWidget(
                label("This URL has already been identified and blocked.", role="muted")
            )
        column.addWidget(
            label(
                f"Confidence {round(result.confidence * 100)}%"
                f"   ·   Evidence strength {round(result.evidence_strength * 100)}%"
                f"   ·   Category: {result.category.replace('_', ' ').title()}",
                role="muted",
            )
        )
        column.addWidget(label(result.url, role="caption"))

        if result.sources:
            column.addWidget(label("Intelligence Sources", role="h2"))
            sources_table = DataTable(["Source", "Risk", "Confidence", "Status"])
            sources_table.set_rows(
                [
                    [
                        s.source.replace("_", " ").upper(),
                        f"{s.risk_percent}%" if s.available else "—",
                        f"{round(s.confidence * 100)}%" if s.available else "—",
                        "Active" if s.available else "Unavailable",
                    ]
                    for s in result.sources
                ]
            )
            sources_table.setMinimumHeight(170)
            column.addWidget(sources_table)

        if result.contributions:
            column.addWidget(label("Why this verdict", role="h2"))
            table = DataTable(["Indicator", "Why it matters"])
            table.set_rows(
                [[c.feature.replace("_", " ").title(), c.detail] for c in result.contributions]
            )
            table.setMinimumHeight(200)
            column.addWidget(table)
        elif not blocked:
            column.addWidget(
                label("No risk indicators detected - the URL looks clean.", role="muted")
            )

        open_button = Button("Open URL", variant="secondary")
        open_button.clicked.connect(lambda: self._guard_open(result.url))
        actions = QHBoxLayout()
        actions.addWidget(open_button)
        actions.addStretch(1)
        column.addLayout(actions)
        return container

    def _guard_open(self, url: str) -> None:
        if not url:
            return
        client = self._context.backend_client
        self._pending_open = url
        self._open_runner.run(lambda: client.guard_open(url))

    def _on_guard_result(self, status: ThreatStatus) -> None:
        if status.blocked and status.threat is not None:
            dialog = ThreatWarningDialog(status.threat, self._context.theme_manager, parent=self)
            dialog.exec()
            return
        QDesktopServices.openUrl(QUrl(self._pending_open))

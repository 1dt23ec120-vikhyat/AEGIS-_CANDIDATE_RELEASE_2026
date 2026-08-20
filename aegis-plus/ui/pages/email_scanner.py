"""Email Scanner page - analyst investigation workspace.

A SOC-style investigation console for a single analyzed email. The result is
presented as a sequence of focused, collapsible sections - executive summary,
overview, authentication, sender intelligence, threat intelligence, embedded
URLs, attachments, timeline, explainable AI, and analyst notes - so an analyst
can triage from the summary and expand only the evidence they need.

All content is derived from the existing analysis pipeline; the page performs no
detection logic of its own.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ui.backend import AsyncRunner, EmailScanResult, InvestigationDTO
from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.empty_state import EmptyState
from ui.components.inputs import SearchBar
from ui.components.section import Section
from ui.components.tables import DataTable
from ui.components.text import SectionTitle, label
from ui.context import UIContext
from ui.navigation.routes import Route
from ui.pages.base_page import BasePage

_VERDICT_TONE = {"legitimate": "success", "suspicious": "warning", "phishing": "danger"}
_AUTH_TONE = {"pass": "success", "warning": "warning", "fail": "danger", "none": "neutral"}
_AUTH_MARK = {"pass": "✓", "warning": "⚠", "fail": "✗", "none": "—"}
_STATUSES = [
    ("open", "Open"),
    ("under_investigation", "Under Investigation"),
    ("confirmed_threat", "Confirmed Threat"),
    ("false_positive", "False Positive"),
    ("resolved", "Resolved"),
]
_PRIORITIES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]
_SAMPLE = (
    "From: PayPal Support <no-reply@paypal-secure-login.xyz>\n"
    "Reply-To: attacker@evil.example\n"
    "To: you@example.com\n"
    "Subject: Urgent: verify your account\n"
    "Date: Tue, 21 Jul 2026 09:14:00 +0000\n"
    "Message-ID: <a1b2c3@paypal-secure-login.xyz>\n"
    "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n\n"
    "Your account is suspended. Click here to verify: http://bit.ly/verify-now\n"
)


class EmailScannerPage(BasePage):
    """Analyst workspace for investigating a single email."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the investigation workspace."""
        super().__init__(
            "Email Investigation",
            "Analyze, investigate, and triage suspicious email",
            parent=parent,
        )
        self._context = context
        self._runner = AsyncRunner(self)
        self._runner.finished.connect(self._on_completed)
        self._body: QWidget | None = None
        self._result: EmailScanResult | None = None
        self._status = QComboBox()
        self._priority = QComboBox()
        self._tags = SearchBar()
        self._notes = QPlainTextEdit()

        self._copilot_action = Button("Ask Copilot", variant="ghost")
        self._copilot_action.clicked.connect(self._ask_copilot)
        self._copilot_action.hide()
        self.header.add_action(self._copilot_action)

        console = Card()
        console.add(SectionTitle("Submit an email"))
        console.add(label("Paste the raw message (headers and body).", role="muted"))
        self._input = QPlainTextEdit()
        self._input.setPlaceholderText(_SAMPLE)
        self._input.setMinimumHeight(150)
        console.add(self._input)
        actions = QHBoxLayout()
        self._button = Button("Investigate", variant="primary")
        self._button.clicked.connect(self._submit)
        sample = Button("Load sample", variant="secondary")
        sample.clicked.connect(lambda: self._input.setPlainText(_SAMPLE))
        actions.addWidget(self._button)
        actions.addWidget(sample)
        actions.addStretch(1)
        console.content_layout.addLayout(actions)
        self.add(console)

        self._workspace = Card()
        self.add(self._workspace)
        self.add_stretch()
        self._set_body(
            EmptyState(
                icon_name="mail",
                title="No investigation open",
                subtitle="Submit a raw email to open an investigation workspace",
            )
        )

    # --- interaction ----------------------------------------------------

    def on_navigated(self, payload: object) -> None:
        """Open the investigation for a persisted scan (deep link).

        Reuses the same rendering path as a fresh analysis. Called by the router
        when another page (e.g. Gmail Intelligence) navigates here with a
        ``{"scan_id": ...}`` payload, so Gmail messages open the *existing* Email
        Investigation workspace rather than a Gmail-specific one.
        """
        if not isinstance(payload, dict):
            return
        scan_id = payload.get("scan_id")
        if not isinstance(scan_id, str) or not scan_id:
            return
        self._button.setEnabled(False)
        self._set_body(label("Loading investigation…", role="muted"))
        client = self._context.backend_client
        self._runner.run(lambda: client.get_email_scan(scan_id))

    def _submit(self) -> None:
        content = self._input.toPlainText().strip()
        if not content:
            return
        self._button.setEnabled(False)
        self._set_body(label("Analyzing…", role="muted"))
        client = self._context.backend_client
        self._runner.run(lambda: client.scan_email(content))

    def _on_completed(self, result: EmailScanResult) -> None:
        self._button.setEnabled(True)
        self._result = result
        self._copilot_action.setVisible(result.ok and bool(result.incident_id or result.sender))
        self._set_body(self._build_workspace(result))

    def _ask_copilot(self) -> None:
        if self._result is None:
            return
        if self._result.incident_id:
            payload: dict[str, object] = {
                "focus": self._result.incident_id,
                "kind": "incident",
                "origin": Route.EMAIL_SCANNER,
            }
        elif self._result.sender:
            payload = {
                "focus": self._result.sender,
                "kind": "artifact",
                "origin": Route.EMAIL_SCANNER,
            }
        else:
            return
        self._context.go_to(Route.COPILOT, payload)

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
            lambda: client.save_investigation(
                scan_id, status=status, priority=priority, tags=tags, notes=notes
            )
        )

    def _set_body(self, widget: QWidget) -> None:
        if self._body is not None:
            self._workspace.content_layout.removeWidget(self._body)
            self._body.deleteLater()
        self._body = widget
        self._workspace.content_layout.addWidget(widget)

    # --- composition ----------------------------------------------------

    def _build_workspace(self, result: EmailScanResult) -> QWidget:
        container = QWidget()
        column = QVBoxLayout(container)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(14)

        if not result.ok:
            column.addWidget(Badge("Investigation failed", tone="danger"))
            column.addWidget(label(result.error or "Unknown error", role="muted"))
            return container

        column.addWidget(self._executive_summary(result))
        column.addWidget(self._overview_section(result))
        column.addWidget(self._authentication_section(result))
        column.addWidget(self._sender_section(result))
        column.addWidget(self._threat_intel_section(result))
        column.addWidget(self._urls_section(result))
        column.addWidget(self._attachments_section(result))
        column.addWidget(self._body_section(result))
        column.addWidget(self._timeline_section(result))
        column.addWidget(self._explanation_section(result))
        column.addWidget(self._notes_section(result))
        return container

    def _executive_summary(self, result: EmailScanResult) -> QWidget:
        card = Card()
        header = QHBoxLayout()
        header.addWidget(
            Badge(result.verdict.upper(), tone=_VERDICT_TONE.get(result.verdict, "neutral"))
        )
        header.addSpacing(8)
        header.addWidget(Badge(result.category.replace("_", " ").title(), tone="info"))
        header.addStretch(1)
        header.addWidget(label(f"{result.risk_percent}% risk", role="h2"))
        card.content_layout.addLayout(header)
        card.add(
            label(
                f"Confidence {round(result.confidence * 100)}%"
                f"   ·   Evidence strength {round(result.evidence_strength * 100)}%"
                f"   ·   {result.malicious_url_count}/{result.url_count} URL(s) malicious"
                f"   ·   {len(result.attachments)} attachment(s)",
                role="muted",
            )
        )
        card.add(label(f"From {result.sender or '(unknown)'}", role="caption"))
        card.add(label(result.subject or "(no subject)", role="body"))
        return card

    def _overview_section(self, result: EmailScanResult) -> QWidget:
        section = Section("Email Overview", expanded=False)
        overview = result.overview
        if overview is None:
            section.add_body(label("No parsed metadata available.", role="muted"))
            return section
        table = DataTable(["Field", "Value"])
        table.set_rows(
            [
                ["Display name", overview.from_display or "—"],
                ["From", overview.from_address or "—"],
                ["To", ", ".join(overview.to) or "—"],
                ["CC", ", ".join(overview.cc) or "—"],
                ["BCC", ", ".join(overview.bcc) or "—"],
                ["Subject", overview.subject or "—"],
                ["Date", overview.date or "—"],
                ["Reply-To", overview.reply_to or "—"],
                ["Return-Path", overview.return_path or "—"],
                ["Message-ID", overview.message_id or "—"],
                ["MIME-Version", overview.mime_version or "—"],
                ["Content-Type", overview.content_type or "—"],
                ["Priority", overview.priority or "—"],
            ]
        )
        table.setMinimumHeight(330)
        section.add_body(table)
        return section

    def _authentication_section(self, result: EmailScanResult) -> QWidget:
        failed = sum(1 for m in result.authentication if m.status == "fail")
        section = Section(
            "Authentication",
            badge=f"{failed} failed" if failed else "All checks passed",
            badge_tone="danger" if failed else "success",
        )
        if not result.authentication:
            section.add_body(label("No authentication data available.", role="muted"))
            return section
        for mechanism in result.authentication:
            row = QWidget()
            layout = QVBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(2)
            head = QHBoxLayout()
            mark = _AUTH_MARK.get(mechanism.status, "—")
            head.addWidget(
                Badge(
                    f"{mark} {mechanism.name}",
                    tone=_AUTH_TONE.get(mechanism.status, "neutral"),
                )
            )
            head.addSpacing(8)
            head.addWidget(label(mechanism.reason, role="body"))
            head.addStretch(1)
            layout.addLayout(head)
            layout.addWidget(label(mechanism.impact, role="caption"))
            section.add_body(row)
        return section

    def _sender_section(self, result: EmailScanResult) -> QWidget:
        intel = result.sender_intel
        tone = "danger" if intel and intel.brand_impersonation else "neutral"
        section = Section(
            "Sender Intelligence",
            badge="Impersonation" if tone == "danger" else "",
            badge_tone=tone,
            expanded=False,
        )
        if intel is None:
            section.add_body(label("No sender intelligence available.", role="muted"))
            return section
        table = DataTable(["Field", "Value"])
        table.set_rows(
            [
                ["Display name", intel.display_name or "—"],
                ["Actual address", intel.address or "—"],
                ["Sender domain", intel.domain or "—"],
                ["Reply-To", intel.reply_to or "—"],
                ["Reply-To mismatch", "Yes" if intel.reply_to_mismatch else "No"],
                [
                    "Brand impersonation",
                    intel.impersonation_detail if intel.brand_impersonation else "Not detected",
                ],
                ["Previous scans (sender)", str(intel.prior_scans)],
                ["Previous malicious", str(intel.prior_malicious)],
            ]
        )
        table.setMinimumHeight(230)
        section.add_body(table)
        return section

    def _threat_intel_section(self, result: EmailScanResult) -> QWidget:
        section = Section(
            "Threat Intelligence",
            badge="Blacklisted" if result.malicious else "Not listed",
            badge_tone="danger" if result.malicious else "success",
            expanded=False,
        )
        intel = result.sender_intel
        prior = intel.prior_malicious if intel else 0
        section.add_body(
            label(
                (
                    "This email was added to Threat Intelligence as an EMAIL artifact."
                    if result.malicious
                    else "This email was not added to Threat Intelligence."
                ),
                role="body",
            )
        )
        section.add_body(
            label(
                f"Historical malicious detections for this sender: {prior}",
                role="muted",
            )
        )
        table = DataTable(["Source", "Risk", "Confidence", "Status"])
        table.set_rows(
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
        table.setMinimumHeight(220)
        section.add_body(table)
        return section

    def _urls_section(self, result: EmailScanResult) -> QWidget:
        section = Section(
            "Embedded URLs",
            badge=f"{result.malicious_url_count}/{result.url_count} malicious",
            badge_tone="danger" if result.malicious_url_count else "neutral",
            expanded=bool(result.urls),
        )
        if not result.urls:
            section.add_body(label("No URLs were found in this message.", role="muted"))
            return section
        table = DataTable(["URL", "Verdict", "Risk", "Threat Intelligence"])
        table.set_rows(
            [
                [
                    u.url,
                    u.verdict.title(),
                    f"{u.risk_percent}%",
                    "Blacklisted" if u.blacklisted else "Not listed",
                ]
                for u in result.urls
            ]
        )
        table.setMinimumHeight(140)
        section.add_body(table)
        section.add_body(
            label(
                "Each URL was analyzed by the URL Intelligence Engine "
                "(ML, heuristic, domain, and threat intelligence).",
                role="caption",
            )
        )
        return section

    def _attachments_section(self, result: EmailScanResult) -> QWidget:
        risky = sum(1 for a in result.attachments if a.indicators)
        section = Section(
            "Attachments",
            badge=f"{risky} risky" if risky else f"{len(result.attachments)} attached",
            badge_tone="danger" if risky else "neutral",
            expanded=bool(result.attachments),
        )
        if not result.attachments:
            section.add_body(label("No attachments in this message.", role="muted"))
            return section
        table = DataTable(["Filename", "Type", "Size", "SHA-256", "Indicators", "Malware Scan"])
        table.set_rows(
            [
                [
                    a.filename,
                    a.content_type,
                    f"{a.size} B",
                    f"{a.sha256[:16]}…",
                    "; ".join(a.indicators) or "None",
                    a.malware_scan.replace("_", " ").title(),
                ]
                for a in result.attachments
            ]
        )
        table.setMinimumHeight(140)
        section.add_body(table)
        section.add_body(
            label(
                "Metadata analysis only. YARA, malware scanning, and sandbox "
                "detonation are future integrations.",
                role="caption",
            )
        )
        return section

    def _body_section(self, result: EmailScanResult) -> QWidget:
        section = Section("Message Body", expanded=False)
        body = result.body
        if body is None:
            section.add_body(label("No message body available.", role="muted"))
            return section
        tabs = QTabWidget()
        for title, content in (
            ("Plain Text", body.plain),
            ("HTML", body.html),
            ("Source (Raw MIME)", body.raw),
        ):
            view = QPlainTextEdit()
            view.setReadOnly(True)
            view.setPlainText(content or "(empty)")
            view.setMinimumHeight(220)
            tabs.addTab(view, title)
        section.add_body(tabs)
        return section

    def _timeline_section(self, result: EmailScanResult) -> QWidget:
        section = Section("Timeline", expanded=False)
        events = [
            ["Email received", "Submitted for analysis"],
            ["Analysis performed", f"{len(result.sources)} intelligence sources consulted"],
            [
                "URLs analyzed",
                f"{result.url_count} URL(s) via the URL Intelligence Engine",
            ],
        ]
        if result.malicious:
            events.append(["Threat detected", f"{result.category.replace('_', ' ').title()}"])
            events.append(["Threat added", "Recorded in Threat Intelligence (EMAIL)"])
            events.append(["Threat blocked", "Sender identity blacklisted"])
        else:
            events.append(["No threat recorded", "Verdict did not meet the malicious threshold"])
        intel = result.sender_intel
        if intel and intel.prior_scans:
            events.append(
                [
                    "Previous detections",
                    f"{intel.prior_malicious} malicious of {intel.prior_scans} prior scans",
                ]
            )
        table = DataTable(["Event", "Detail"])
        table.set_rows(events)
        table.setMinimumHeight(200)
        section.add_body(table)
        return section

    def _explanation_section(self, result: EmailScanResult) -> QWidget:
        section = Section(
            "Explainable AI",
            badge=f"{len(result.contributions)} indicators",
            badge_tone="info",
        )
        if not result.contributions:
            section.add_body(label("No indicators were triggered.", role="muted"))
            return section
        table = DataTable(["Indicator", "Why it matters", "Weight"])
        table.set_rows(
            [
                [c.feature.replace("_", " ").title(), c.detail, f"{c.weight:.2f}"]
                for c in result.contributions
            ]
        )
        table.setMinimumHeight(190)
        section.add_body(table)
        return section

    def _notes_section(self, result: EmailScanResult) -> QWidget:
        section = Section("Analyst Notes", expanded=False)
        investigation = InvestigationDTO(scan_id=result.scan_id)
        if result.scan_id:
            investigation = self._context.backend_client.get_investigation(result.scan_id)

        self._status = QComboBox()
        for _, text in _STATUSES:
            self._status.addItem(text)
        self._status.setCurrentIndex(
            next((i for i, (key, _) in enumerate(_STATUSES) if key == investigation.status), 0)
        )
        self._priority = QComboBox()
        for _, text in _PRIORITIES:
            self._priority.addItem(text)
        self._priority.setCurrentIndex(
            next(
                (i for i, (key, _) in enumerate(_PRIORITIES) if key == investigation.priority),
                1,
            )
        )
        self._tags = SearchBar()
        self._tags.setPlaceholderText("Tags (comma separated)")
        self._tags.setText(", ".join(investigation.tags))
        self._notes = QPlainTextEdit()
        self._notes.setPlaceholderText("Investigation notes…")
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

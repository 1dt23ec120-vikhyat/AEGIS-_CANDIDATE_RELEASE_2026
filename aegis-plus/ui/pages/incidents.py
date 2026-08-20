"""Incidents page - incident and campaign investigation.

Lists correlated incidents and discovered campaigns, and opens a selected
incident as an investigation view: executive summary, correlated evidence
(artifacts), affected users, campaign attribution, chronological history, and the
analyst workflow controls (assignment, priority, status, comments).

Detection evidence is read-only here; only workflow fields can be changed.
"""

from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QVBoxLayout, QWidget

from ui.backend import AsyncRunner, CampaignDTO, IncidentDTO
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

_STATUS_TONE = {
    "open": "danger",
    "investigating": "warning",
    "contained": "info",
    "resolved": "success",
    "false_positive": "neutral",
}
_STATUSES = [
    ("open", "Open"),
    ("investigating", "Investigating"),
    ("contained", "Contained"),
    ("resolved", "Resolved"),
    ("false_positive", "False Positive"),
]
_PRIORITIES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]
_INCIDENT_COLUMNS = ["Title", "Category", "Risk", "Status", "Priority", "Detections", "Users"]
_CAMPAIGN_COLUMNS = ["Campaign", "Category", "Risk", "Occurrences", "Affected Users"]


class IncidentsPage(BasePage):
    """Track, correlate, and triage security incidents."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the incidents page."""
        super().__init__(
            "Incidents",
            "Correlated incidents and discovered campaigns",
            parent=parent,
        )
        self._context = context
        self._runner = AsyncRunner(self)
        self._runner.finished.connect(self._on_loaded)
        self._incidents: tuple[IncidentDTO, ...] = ()
        self._campaigns: tuple[CampaignDTO, ...] = ()
        self._selected: IncidentDTO | None = None
        self._detail_body: QWidget | None = None
        self._status = QComboBox()
        self._priority = QComboBox()
        self._assignee = SearchBar()
        self._comment = SearchBar()

        self._copilot_action = Button("Ask Copilot", variant="ghost")
        self._copilot_action.clicked.connect(self._ask_copilot)
        self._copilot_action.setEnabled(False)
        self.header.add_action(self._copilot_action)

        controls = Card()
        controls.add(SectionTitle("Incident queue"))
        row = QHBoxLayout()
        refresh = Button("Refresh", variant="primary")
        refresh.clicked.connect(self.refresh)
        row.addWidget(refresh)
        row.addStretch(1)
        controls.content_layout.addLayout(row)
        self._table = DataTable(_INCIDENT_COLUMNS)
        self._table.currentCellChanged.connect(lambda *_: self._on_select())
        self._table.setMinimumHeight(220)
        controls.add(self._table)
        self.add(controls)

        self._campaign_section = Section("Campaigns", expanded=True)
        self._campaign_table = DataTable(_CAMPAIGN_COLUMNS)
        self._campaign_table.setMinimumHeight(160)
        self._campaign_section.add_body(self._campaign_table)
        self.add(self._campaign_section)

        self._detail = Card()
        self._detail.add(SectionTitle("Investigation"))
        self.add(self._detail)
        self.add_stretch()
        self._set_detail(
            EmptyState(
                icon_name="alert",
                title="No incident selected",
                subtitle="Refresh the queue and select an incident to investigate",
            )
        )

    # --- data -----------------------------------------------------------

    def refresh(self) -> None:
        """Reload incidents and campaigns from the backend."""
        client = self._context.backend_client
        self._runner.run(lambda: (client.list_incidents(), client.list_campaigns()))

    def _on_loaded(self, payload: object) -> None:
        if not isinstance(payload, tuple):
            return
        incidents, campaigns = payload
        self._incidents = tuple(incidents)
        self._campaigns = tuple(campaigns)
        self._table.set_rows(
            [
                [
                    i.title,
                    i.category.replace("_", " ").title(),
                    f"{i.risk_percent}%",
                    i.status.replace("_", " ").title(),
                    i.priority.title(),
                    str(i.occurrences),
                    str(len(i.affected_users)),
                ]
                for i in self._incidents
            ]
        )
        self._campaign_table.set_rows(
            [
                [
                    c.name,
                    c.category.replace("_", " ").title(),
                    f"{c.risk_percent}%",
                    str(c.occurrences),
                    str(len(c.affected_users)),
                ]
                for c in self._campaigns
            ]
        )
        if self._incidents:
            self._select(self._incidents[0])

    def _on_select(self) -> None:
        index = self._table.currentRow()
        if 0 <= index < len(self._incidents):
            self._select(self._incidents[index])

    def _select(self, incident: IncidentDTO) -> None:
        self._selected = incident
        self._copilot_action.setEnabled(bool(incident.id))
        self._set_detail(self._build_detail(incident))

    def _ask_copilot(self) -> None:
        if self._selected is None or not self._selected.id:
            return
        self._context.go_to(
            Route.COPILOT,
            {
                "focus": self._selected.id,
                "kind": "incident",
                "origin": Route.INCIDENTS,
            },
        )

    def _apply_workflow(self) -> None:
        if self._selected is None or not self._selected.id:
            return
        client = self._context.backend_client
        incident_id = self._selected.id
        status = _STATUSES[self._status.currentIndex()][0]
        priority = _PRIORITIES[self._priority.currentIndex()][0]
        assignee = self._assignee.text().strip()
        comment = self._comment.text().strip() or None

        def apply_and_reload() -> tuple[list[IncidentDTO], list[CampaignDTO]]:
            client.update_incident(
                incident_id,
                status=status,
                priority=priority,
                assignee=assignee,
                comment=comment,
            )
            return client.list_incidents(), client.list_campaigns()

        self._runner.run(apply_and_reload)

    def _set_detail(self, widget: QWidget) -> None:
        if self._detail_body is not None:
            self._detail.content_layout.removeWidget(self._detail_body)
            self._detail_body.deleteLater()
        self._detail_body = widget
        self._detail.content_layout.addWidget(widget)

    # --- composition ----------------------------------------------------

    def _build_detail(self, incident: IncidentDTO) -> QWidget:
        container = QWidget()
        column = QVBoxLayout(container)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(14)

        header = QHBoxLayout()
        header.addWidget(
            Badge(
                incident.status.replace("_", " ").upper(),
                tone=_STATUS_TONE.get(incident.status, "neutral"),
            )
        )
        header.addSpacing(8)
        header.addWidget(Badge(incident.priority.upper(), tone="warning"))
        header.addStretch(1)
        header.addWidget(label(f"{incident.risk_percent}% risk", role="h2"))
        column.addLayout(header)
        column.addWidget(label(incident.title, role="body"))
        column.addWidget(
            label(
                f"Category {incident.category.replace('_', ' ').title()}"
                f"   ·   {incident.occurrences} detection(s)"
                f"   ·   {len(incident.affected_users)} affected user(s)"
                f"   ·   Owner {incident.assignee or 'unassigned'}",
                role="muted",
            )
        )
        column.addWidget(self._campaign_panel(incident))
        column.addWidget(self._evidence_panel(incident))
        column.addWidget(self._users_panel(incident))
        column.addWidget(self._timeline_panel(incident))
        column.addWidget(self._workflow_panel(incident))
        return container

    def _campaign_panel(self, incident: IncidentDTO) -> QWidget:
        campaign = next((c for c in self._campaigns if c.id == incident.campaign_id), None)
        section = Section(
            "Campaign",
            badge=campaign.name if campaign else "Unattributed",
            badge_tone="info" if campaign else "neutral",
            expanded=False,
        )
        if campaign is None:
            section.add_body(label("This incident is not part of a campaign.", role="muted"))
            return section
        table = DataTable(["Field", "Value"])
        table.set_rows(
            [
                ["Name", campaign.name],
                ["Category", campaign.category.replace("_", " ").title()],
                ["Risk", f"{campaign.risk_percent}%"],
                ["Occurrences", str(campaign.occurrences)],
                ["Affected users", ", ".join(campaign.affected_users) or "—"],
                ["First seen", campaign.first_seen[:19].replace("T", " ")],
                ["Last seen", campaign.last_seen[:19].replace("T", " ")],
            ]
        )
        table.setMinimumHeight(200)
        section.add_body(table)
        return section

    def _evidence_panel(self, incident: IncidentDTO) -> QWidget:
        section = Section(
            "Correlated Evidence",
            badge=f"{len(incident.artifacts)} artifacts",
            badge_tone="info",
        )
        if not incident.artifacts:
            section.add_body(label("No artifacts recorded.", role="muted"))
            return section
        table = DataTable(["Kind", "Observable"])
        table.set_rows([[a.kind.replace("_", " ").title(), a.value] for a in incident.artifacts])
        table.setMinimumHeight(200)
        section.add_body(table)
        return section

    def _users_panel(self, incident: IncidentDTO) -> QWidget:
        section = Section(
            "Affected Users",
            badge=str(len(incident.affected_users)),
            badge_tone="warning" if incident.affected_users else "neutral",
            expanded=False,
        )
        if not incident.affected_users:
            section.add_body(label("No recipients recorded.", role="muted"))
            return section
        table = DataTable(["Recipient"])
        table.set_rows([[user] for user in incident.affected_users])
        table.setMinimumHeight(130)
        section.add_body(table)
        return section

    def _timeline_panel(self, incident: IncidentDTO) -> QWidget:
        section = Section(
            "Timeline",
            badge=f"{len(incident.events)} events",
            badge_tone="info",
        )
        if not incident.events:
            section.add_body(label("No history recorded.", role="muted"))
            return section
        table = DataTable(["When", "Event", "Detail"])
        table.set_rows(
            [[e.occurred_at[:19].replace("T", " "), e.label, e.detail] for e in incident.events]
        )
        table.setMinimumHeight(190)
        section.add_body(table)
        return section

    def _workflow_panel(self, incident: IncidentDTO) -> QWidget:
        section = Section("Analyst Workflow", expanded=False)
        self._status = QComboBox()
        for _, text in _STATUSES:
            self._status.addItem(text)
        self._status.setCurrentIndex(
            next((i for i, (k, _) in enumerate(_STATUSES) if k == incident.status), 0)
        )
        self._priority = QComboBox()
        for _, text in _PRIORITIES:
            self._priority.addItem(text)
        self._priority.setCurrentIndex(
            next((i for i, (k, _) in enumerate(_PRIORITIES) if k == incident.priority), 1)
        )
        self._assignee = SearchBar()
        self._assignee.setPlaceholderText("Assignee")
        self._assignee.setText(incident.assignee)
        self._comment = SearchBar()
        self._comment.setPlaceholderText("Add a comment…")

        row = QHBoxLayout()
        row.addWidget(label("Status", role="muted"))
        row.addWidget(self._status)
        row.addSpacing(12)
        row.addWidget(label("Priority", role="muted"))
        row.addWidget(self._priority)
        row.addStretch(1)
        section.body_layout.addLayout(row)
        section.add_body(self._assignee)
        section.add_body(self._comment)

        actions = QHBoxLayout()
        apply_button = Button("Apply", variant="primary")
        apply_button.clicked.connect(self._apply_workflow)
        actions.addWidget(apply_button)
        actions.addStretch(1)
        section.body_layout.addLayout(actions)
        return section

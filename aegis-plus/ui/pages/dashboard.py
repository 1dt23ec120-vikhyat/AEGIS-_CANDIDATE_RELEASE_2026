"""SOC Command Center.

The operational heart of AEGIS+ and the first screen an analyst sees. The page is
ordered by operational priority - executive overview, critical incidents,
campaigns, timeline, threat intelligence, analytics, platform health, analyst
activity - so the most decision-relevant information is read first.

Every widget is a view over a single ``/api/soc/overview`` response, so the whole
dashboard costs one request; a future auto-refresh or push update only needs to
re-invoke :meth:`DashboardPage.refresh` with the same payload shape. The page
holds no detection or aggregation logic.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QVBoxLayout, QWidget

from core.domain.soc_analytics_view import AnalyticsOverview
from ui.backend import AsyncRunner, MetricDTO, SocOverviewDTO
from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.chart import MiniBarChart
from ui.components.section import Section
from ui.components.soc_cards import CampaignCard, IncidentCard
from ui.components.tables import DataTable
from ui.components.text import SectionTitle, label
from ui.components.tiles import NOT_REPORTED, HealthTile, MetricTile
from ui.components.timeline import (
    SkeletonPanel,
    StatusPanel,
    TimelineEntry,
    TimelineView,
)
from ui.context import UIContext
from ui.navigation import Route
from ui.pages.base_page import BasePage

_LEVEL_TONE = {
    "Critical": "danger",
    "Elevated": "warning",
    "Guarded": "warning",
    "Normal": "success",
}
_METRIC_ICONS = {
    "Threat level": "shield",
    "Overall risk": "chip",
    "Open incidents": "alert",
    "Active campaigns": "report",
    "Threat intelligence hits": "shield",
    "Blocked threats": "shield",
    "Critical alerts": "bell",
    "Platform": "settings",
}
_METRIC_DESCRIPTIONS = {
    "Threat level": "Current operational posture",
    "Overall risk": "Weighted across open incidents",
    "Open incidents": "Awaiting analyst action",
    "Active campaigns": "Correlated attack groupings",
    "Threat intelligence hits": "Artifacts on the blacklist",
    "Blocked threats": "Automatically contained",
    "Critical alerts": "Highest severity open work",
    "Platform": "Subsystem availability",
}
_OVERVIEW_COLUMNS = 4
_CARD_COLUMNS = 2
_TIMELINE_ROWS = 10
_SECONDS_PER_MINUTE = 60
_MINUTES_PER_HOUR = 60
_HOURS_PER_DAY = 24


def _relative_age(timestamp: str) -> str:
    """Render an ISO timestamp as a compact age such as ``3m`` or ``2h``."""
    try:
        moment = datetime.fromisoformat(timestamp)
    except ValueError:
        return "unknown"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    seconds = (datetime.now(UTC) - moment).total_seconds()
    if seconds < _SECONDS_PER_MINUTE:
        return "just now"
    minutes = seconds / _SECONDS_PER_MINUTE
    if minutes < _MINUTES_PER_HOUR:
        return f"{int(minutes)}m ago"
    hours = minutes / _MINUTES_PER_HOUR
    if hours < _HOURS_PER_DAY:
        return f"{int(hours)}h ago"
    return f"{int(hours / _HOURS_PER_DAY)}d ago"


def _day_group(timestamp: str) -> str:
    """Group label for a timestamp: Today, Yesterday, or the date."""
    try:
        moment = datetime.fromisoformat(timestamp)
    except ValueError:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    days = (datetime.now(UTC).date() - moment.date()).days
    if days <= 0:
        return "Today"
    if days == 1:
        return "Yesterday"
    return moment.strftime("%d %b %Y")


def _version_for(component: str) -> str:
    """Version string for a subsystem, when the platform reports one."""
    # The overview payload does not carry per-subsystem versions, so the tile
    # reports them as unavailable rather than inventing a value.
    return ""


def _mode_for(status: str) -> str:
    """Operating mode derived from the reported status."""
    return {"healthy": "Active", "disabled": "Disabled"}.get(status.lower(), "")


def _clock(timestamp: str) -> str:
    return timestamp[11:19] if len(timestamp) >= 19 else timestamp  # noqa: PLR2004


class DashboardPage(BasePage):
    """Unified operational overview of the AEGIS+ platform."""

    def __init__(self, context: UIContext, *, parent: QWidget | None = None) -> None:
        """Build the SOC command centre."""
        super().__init__(
            "SOC Command Center",
            "Unified operational picture across every AEGIS+ capability",
            parent=parent,
        )
        self._context = context
        self._theme = context.theme_manager
        self._runner = AsyncRunner(self)
        self._runner.finished.connect(self._on_loaded)
        self._advanced_runner = AsyncRunner(self)
        self._advanced_runner.finished.connect(self._on_analytics)
        self._body: QWidget | None = None

        self._copilot_action = Button("Ask Copilot", variant="ghost")
        self._copilot_action.setToolTip("Open the AI Security Copilot for a posture summary")
        self._copilot_action.clicked.connect(self._ask_copilot)
        self.header.add_action(self._copilot_action)

        spacing = self._theme.theme.spacing
        bar = Card()
        bar.content_layout.setSpacing(spacing.sm)
        row = QHBoxLayout()
        row.setSpacing(spacing.sm)
        self._level_badge = Badge("LOADING", tone="neutral")
        self._level_badge.setToolTip("Current operational threat level")
        row.addWidget(self._level_badge)
        self._status_badges: dict[str, Badge] = {}
        for key, text, tip in (
            ("incidents", "INCIDENTS —", "Open incidents awaiting analyst action"),
            ("campaigns", "CAMPAIGNS —", "Active correlated campaigns"),
            ("platform", "PLATFORM —", "Aggregate subsystem availability"),
            ("backend", "BACKEND —", "Embedded backend connectivity"),
        ):
            badge = Badge(text, tone="neutral")
            badge.setToolTip(tip)
            self._status_badges[key] = badge
            row.addWidget(badge)
        row.addStretch(1)
        self._auto_refresh = Badge("AUTO-REFRESH: MANUAL", tone="neutral")
        self._auto_refresh.setToolTip(
            "Automatic refresh is not yet enabled; use Refresh to update."
        )
        row.addWidget(self._auto_refresh)
        self._generated = label("Awaiting platform data", role="caption")
        row.addWidget(self._generated)
        refresh = Button("Refresh", variant="primary")
        refresh.setToolTip("Reload the operational picture")
        refresh.clicked.connect(self.refresh)
        row.addWidget(refresh)
        bar.content_layout.addLayout(row)
        self.add(bar)

        self._workspace = Card(flat=True)
        self.add(self._workspace)
        self._advanced = Card(flat=True)
        self.add(self._advanced)
        self.add_stretch()
        self._show_loading()
        self.refresh()

    # --- data -----------------------------------------------------------

    def refresh(self) -> None:
        """Reload the whole dashboard from one aggregated request."""
        self._show_loading()
        client = self._context.backend_client
        self._runner.run(client.soc_overview)
        self._advanced_runner.run(lambda: client.analytics_overview(top=5))

    def _ask_copilot(self) -> None:
        """Open the Copilot with a global (posture) focus."""
        self._context.go_to(
            Route.COPILOT,
            {"kind": "global", "origin": Route.DASHBOARD},
        )

    def _show_loading(self) -> None:
        holder = QWidget()
        column = QVBoxLayout(holder)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(12)
        column.addWidget(
            StatusPanel(
                self._theme,
                title="Loading operational picture",
                message="Collecting incidents, campaigns, intelligence and health…",
                icon_name="dashboard",
            )
        )
        grid = QGridLayout()
        grid.setSpacing(10)
        for index in range(4):
            grid.addWidget(SkeletonPanel(self._theme, rows=3), index // 2, index % 2)
        column.addLayout(grid)
        self._set_body(holder)

    def _on_loaded(self, overview: object) -> None:
        if not isinstance(overview, SocOverviewDTO):
            return
        if not overview.ok:
            self._level_badge.setText("OFFLINE")
            self._status_badges["backend"].setText("BACKEND UNREACHABLE")
            self._generated.setText("Awaiting backend")
            self._set_body(self._unavailable_state())
            return
        self._level_badge.setText(f"THREAT LEVEL: {overview.threat_level.upper()}")
        posture = {m.label: m.value for m in overview.posture}
        self._status_badges["incidents"].setText(f"INCIDENTS {posture.get('Open incidents', '—')}")
        self._status_badges["campaigns"].setText(
            f"CAMPAIGNS {posture.get('Active campaigns', '—')}"
        )
        self._status_badges["platform"].setText(f"PLATFORM {overview.platform_status.upper()}")
        self._status_badges["backend"].setText("BACKEND ONLINE")
        self._generated.setText(f"Updated {_clock(overview.generated_at)}")
        self._set_body(self._build(overview))

    def _on_analytics(self, result: object) -> None:
        """Render the M11 advanced-analytics widgets (additive section)."""
        if not isinstance(result, AnalyticsOverview):
            return
        section = Section("Advanced Threat Analytics", expanded=False)
        section.add_body(
            label("Deterministic analytics from the intelligence engine", role="caption")
        )
        if result.threat_priorities:
            section.add_body(label("Threat priorities", role="caption"))
            table = DataTable(["Artifact", "Urgency", "Priority", "Blast"])
            table.set_rows(
                [
                    [
                        s.label or s.artifact_id,
                        f"{s.analyst_urgency * 100:.0f}%",
                        f"{s.priority * 100:.0f}%",
                        str(s.blast_radius),
                    ]
                    for s in result.threat_priorities
                ]
            )
            table.setMinimumHeight(130)
            section.add_body(table)
        if result.recommendations:
            section.add_body(label("Analyst recommendations", role="caption"))
            for rec in result.recommendations:
                why = rec.rationale[0] if rec.rationale else ""
                section.add_body(label(f"\u2022 {rec.title} \u2014 {why}", role="muted"))
        section.add_body(self._pair_table("Threat distribution", result.threat_distribution))
        if result.infrastructure_reuse:
            section.add_body(label("Infrastructure reuse", role="caption"))
            table = DataTable(["Infrastructure", "Members"])
            table.set_rows(
                [
                    [cluster.infra_label or cluster.infra_id, str(len(cluster.member_ids))]
                    for cluster in result.infrastructure_reuse
                ]
            )
            table.setMinimumHeight(110)
            section.add_body(table)
        if result.emerging_campaigns:
            section.add_body(label("Emerging campaigns", role="caption"))
            table = DataTable(["Campaign", "Artifacts", "IOCs"])
            table.set_rows(
                [
                    [c.label or c.campaign_id, str(c.artifact_count), str(c.ioc_count)]
                    for c in result.emerging_campaigns
                ]
            )
            table.setMinimumHeight(110)
            section.add_body(table)
        if result.ioc_trends:
            section.add_body(label("IOC trends", role="caption"))
            table = DataTable(["IOC", "Frequency", "Confidence"])
            table.set_rows(
                [
                    [i.label or i.ioc_id, str(i.frequency), f"{i.confidence * 100:.0f}%"]
                    for i in result.ioc_trends
                ]
            )
            table.setMinimumHeight(110)
            section.add_body(table)
        self._set_advanced(section)

    def _set_advanced(self, widget: QWidget) -> None:
        layout = self._advanced.content_layout
        while layout.count():
            item = layout.takeAt(0)
            if item is None:
                continue
            existing = item.widget()
            if existing is not None:
                existing.deleteLater()
        layout.addWidget(widget)

    def _set_body(self, widget: QWidget) -> None:
        if self._body is not None:
            self._workspace.content_layout.removeWidget(self._body)
            self._body.deleteLater()
        self._body = widget
        self._workspace.content_layout.addWidget(widget)

    def _unavailable_state(self) -> QWidget:
        holder = QWidget()
        column = QVBoxLayout(holder)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(12)
        column.addWidget(
            StatusPanel(
                self._theme,
                title="Waiting for the platform",
                message=(
                    "The AEGIS+ backend is starting or temporarily unreachable. "
                    "The command centre will populate automatically once the "
                    "service responds — select Refresh to retry now."
                ),
                icon_name="settings",
                tone="warning",
            )
        )
        retry = QHBoxLayout()
        button = Button("Retry connection", variant="secondary")
        button.clicked.connect(self.refresh)
        retry.addWidget(button)
        retry.addStretch(1)
        column.addLayout(retry)
        return holder

    # --- composition ----------------------------------------------------

    def _build(self, overview: SocOverviewDTO) -> QWidget:
        container = QWidget()
        column = QVBoxLayout(container)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(18)
        column.addWidget(self._executive_overview(overview))
        column.addWidget(self._quick_actions(overview))
        column.addWidget(self._incident_section(overview))
        column.addWidget(self._campaign_section(overview))
        column.addWidget(self._timeline_section(overview))
        column.addWidget(self._threat_section(overview))
        column.addWidget(self._analytics_section(overview))
        column.addWidget(self._health_section(overview))
        column.addWidget(self._analyst_section(overview))
        return container

    def _executive_overview(self, overview: SocOverviewDTO) -> QWidget:
        holder = QWidget()
        column = QVBoxLayout(holder)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(10)
        column.addWidget(SectionTitle("Executive Security Overview"))
        grid = QGridLayout()
        grid.setSpacing(12)
        trend = overview.detection_trend
        delta = ""
        direction = "flat"
        if len(trend) >= _CARD_COLUMNS:
            today, yesterday = trend[-1][1], trend[-2][1]
            if today != yesterday:
                direction = "up" if today > yesterday else "down"
                delta = f"{abs(today - yesterday)} vs yesterday"
        for index, metric in enumerate(overview.posture):
            grid.addWidget(
                MetricTile(
                    self._theme,
                    metric=metric.label,
                    value=metric.value,
                    icon_name=_METRIC_ICONS.get(metric.label, "shield"),
                    tone=metric.tone,
                    description=_METRIC_DESCRIPTIONS.get(metric.label, metric.detail),
                    trend=delta if metric.label == "Open incidents" else "",
                    trend_direction=direction,
                ),
                index // _OVERVIEW_COLUMNS,
                index % _OVERVIEW_COLUMNS,
            )
        column.addLayout(grid)
        column.addWidget(
            label(
                f"Last intelligence update {_clock(overview.generated_at)}"
                f"  ·  platform {overview.platform_status.lower()}",
                role="caption",
            )
        )
        return holder

    def _quick_actions(self, overview: SocOverviewDTO) -> QWidget:
        """Shortcuts into the surfaces an analyst reaches for most often."""
        card = Card()
        card.content_layout.setSpacing(self._theme.theme.spacing.md)
        card.add(label("OPERATIONS", role="caption"))
        row = QHBoxLayout()
        row.setSpacing(self._theme.theme.spacing.sm)
        actions: list[tuple[str, str, object]] = []
        if overview.incident_queue:
            actions.append(
                (
                    "Investigate critical incident",
                    overview.incident_queue[0].title,
                    Route.INCIDENTS,
                )
            )
        actions.extend(
            [
                ("Incident queue", "All correlated incidents", Route.INCIDENTS),
                ("Campaign overview", "Discovered campaigns", Route.INCIDENTS),
                ("Threat intelligence", "Blacklisted artifacts", Route.THREAT_INTEL),
            ]
        )
        for text, tip, route in actions:
            button = Button(text, variant="secondary")
            button.setToolTip(str(tip))
            button.clicked.connect(lambda _=False, r=route: self._context.go_to(r))
            row.addWidget(button)
        refresh = Button("Refresh intelligence", variant="secondary")
        refresh.setToolTip("Reload the operational picture")
        refresh.clicked.connect(self.refresh)
        row.addWidget(refresh)
        row.addStretch(1)
        card.content_layout.addLayout(row)
        return card

    def _incident_section(self, overview: SocOverviewDTO) -> QWidget:
        section = Section(
            "Critical Incidents",
            badge=f"{len(overview.incident_queue)} open",
            badge_tone="danger" if overview.incident_queue else "success",
        )
        section.add_body(self._metric_strip(overview.incident_metrics))
        if not overview.incident_queue:
            section.add_body(
                StatusPanel(
                    self._theme,
                    title="No incidents detected",
                    message="No correlated incidents require analyst attention.",
                    icon_name="alert",
                    tone="success",
                )
            )
        else:
            grid = QGridLayout()
            grid.setSpacing(12)
            for index, incident in enumerate(overview.incident_queue):
                card = IncidentCard(
                    self._theme,
                    title=incident.title,
                    category=incident.category,
                    risk_percent=incident.risk_percent,
                    status=incident.status,
                    priority=incident.priority,
                    owner=incident.assignee,
                    affected_users=incident.affected_users,
                    detections=incident.occurrences,
                    age=_relative_age(incident.last_seen),
                )
                card.clicked.connect(lambda: self._context.go_to(Route.INCIDENTS))
                grid.addWidget(card, index // _CARD_COLUMNS, index % _CARD_COLUMNS)
            section.body_layout.addLayout(grid)
        if overview.priority_distribution:
            section.add_body(
                label(
                    "Priority mix: "
                    + "   ".join(
                        f"{name.title()} {count}" for name, count in overview.priority_distribution
                    ),
                    role="caption",
                )
            )
        section.body_layout.addLayout(self._drill_row("Open incident queue", Route.INCIDENTS))
        return section

    def _campaign_section(self, overview: SocOverviewDTO) -> QWidget:
        section = Section(
            "Campaign Overview",
            badge=f"{len(overview.campaigns)} active",
            badge_tone="warning" if overview.campaigns else "success",
        )
        section.add_body(self._metric_strip(overview.campaign_metrics))
        if not overview.campaigns:
            section.add_body(
                StatusPanel(
                    self._theme,
                    title="No active campaigns",
                    message="No correlated attack campaigns have been discovered.",
                    icon_name="report",
                    tone="success",
                )
            )
            return section
        grid = QGridLayout()
        grid.setSpacing(12)
        for index, campaign in enumerate(overview.campaigns):
            card = CampaignCard(
                self._theme,
                name=campaign.name,
                category=campaign.category,
                risk_percent=campaign.risk_percent,
                occurrences=campaign.occurrences,
                affected_users=campaign.affected_users,
                first_seen=_clock(campaign.first_seen),
                last_seen=_relative_age(campaign.last_seen),
                growth=f"{campaign.occurrences} detection(s) so far",
                incident_count=NOT_REPORTED,
                status="Active",
            )
            card.clicked.connect(lambda: self._context.go_to(Route.INCIDENTS))
            grid.addWidget(card, index // _CARD_COLUMNS, index % _CARD_COLUMNS)
        section.body_layout.addLayout(grid)
        return section

    def _timeline_section(self, overview: SocOverviewDTO) -> QWidget:
        section = Section(
            "Threat Timeline",
            badge=f"{len(overview.timeline)} events",
            badge_tone="info",
        )
        if not overview.timeline:
            section.add_body(
                StatusPanel(
                    self._theme,
                    title="No activity recorded",
                    message="Analyzed artifacts and investigation events appear here.",
                    icon_name="bell",
                )
            )
            return section
        entries = [
            TimelineEntry(
                timestamp=_clock(event.timestamp),
                title=event.title,
                detail=event.detail,
                severity=event.severity,
                kind=event.kind,
                artifact_type=event.artifact_type,
                relative=_relative_age(event.timestamp),
                group=_day_group(event.timestamp),
                extra=(f"Incident {event.incident_id}" if event.incident_id else ""),
            )
            for event in overview.timeline[:_TIMELINE_ROWS]
        ]
        section.add_body(TimelineView(self._theme, entries))
        return section

    def _threat_section(self, overview: SocOverviewDTO) -> QWidget:
        section = Section("Threat Intelligence", expanded=False)
        section.add_body(self._metric_strip(overview.threat_metrics))
        section.add_body(self._pair_table("Top malicious senders", overview.top_malicious_senders))
        section.add_body(self._pair_table("Top malicious URLs", overview.top_malicious_urls))
        section.add_body(self._pair_table("Threat categories", overview.threat_categories))
        section.add_body(self._pair_table("Artifact distribution", overview.artifact_distribution))
        section.body_layout.addLayout(
            self._drill_row("Open threat intelligence", Route.THREAT_INTEL)
        )
        return section

    def _analytics_section(self, overview: SocOverviewDTO) -> QWidget:
        section = Section("Security Analytics", expanded=False)
        section.add_body(self._metric_strip(overview.analytics))
        if overview.detection_trend:
            section.add_body(label("Detection trend (last 7 days)", role="caption"))
            chart = MiniBarChart(
                self._theme,
                values=[float(count) for _, count in overview.detection_trend],
            )
            chart.setMinimumHeight(110)
            section.add_body(chart)
            section.add_body(
                label(
                    "   ".join(f"{day} · {count}" for day, count in overview.detection_trend),
                    role="caption",
                )
            )
        section.add_body(self._pair_table("Risk distribution", overview.risk_distribution))
        return section

    def _health_section(self, overview: SocOverviewDTO) -> QWidget:
        unhealthy = [h for h in overview.health if h.status not in ("healthy", "disabled")]
        section = Section(
            "Platform Health",
            badge=overview.platform_status,
            badge_tone="success" if not unhealthy else "danger",
        )
        if not overview.health:
            section.add_body(
                StatusPanel(
                    self._theme,
                    title="Health unavailable",
                    message="Subsystem diagnostics will appear once reported.",
                    icon_name="settings",
                )
            )
            return section
        grid = QGridLayout()
        grid.setSpacing(12)
        checked = _clock(overview.generated_at)
        for index, component in enumerate(overview.health):
            grid.addWidget(
                HealthTile(
                    self._theme,
                    name=component.name,
                    status=component.status,
                    detail=component.detail,
                    checked_at=checked,
                    version=_version_for(component.name),
                    latency="",
                    mode=_mode_for(component.status),
                ),
                index // _OVERVIEW_COLUMNS,
                index % _OVERVIEW_COLUMNS,
            )
        section.body_layout.addLayout(grid)
        return section

    def _analyst_section(self, overview: SocOverviewDTO) -> QWidget:
        section = Section("Analyst Activity", expanded=False)
        section.add_body(self._metric_strip(overview.analyst_activity))
        if overview.recent_comments:
            section.add_body(label("Recent notes", role="caption"))
            table = DataTable(["Analyst", "Note"])
            table.set_rows([[author, body] for author, body in overview.recent_comments])
            table.setMinimumHeight(140)
            section.add_body(table)
        else:
            section.add_body(
                StatusPanel(
                    self._theme,
                    title="No analyst notes yet",
                    message="Investigation notes recorded by analysts appear here.",
                    icon_name="report",
                )
            )
        return section

    # --- helpers --------------------------------------------------------

    def _metric_strip(self, metrics: Sequence[MetricDTO]) -> QWidget:
        holder = QWidget()
        grid = QGridLayout(holder)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)
        for index, metric in enumerate(metrics):
            cell = Card()
            cell.add(label(metric.label.upper(), role="caption"))
            value = label(metric.value, role="h2")
            tone = metric.tone if metric.value not in ("0", "n/a") else "neutral"
            palette = self._theme.theme.palette
            color = {
                "danger": palette.danger,
                "warning": palette.warning,
                "success": palette.success,
                "info": palette.info,
            }.get(tone, palette.text)
            value.setStyleSheet(f"color: {color}; font-weight: 700;")
            cell.add(value)
            if metric.detail:
                cell.add(label(metric.detail, role="caption"))
            grid.addWidget(cell, index // _OVERVIEW_COLUMNS, index % _OVERVIEW_COLUMNS)
        return holder

    def _pair_table(self, title: str, pairs: Sequence[tuple[str, int]]) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(label(title, role="caption"))
        if not pairs:
            layout.addWidget(label("No data recorded yet.", role="muted"))
            return holder
        table = DataTable(["Value", "Count"])
        table.set_rows([[name, str(count)] for name, count in pairs])
        table.setMinimumHeight(130)
        layout.addWidget(table)
        return holder

    def _drill_row(self, text: str, route: Route) -> QHBoxLayout:
        row = QHBoxLayout()
        button = Button(text, variant="secondary")
        button.clicked.connect(lambda: self._context.go_to(route))
        row.addWidget(button)
        row.addStretch(1)
        return row

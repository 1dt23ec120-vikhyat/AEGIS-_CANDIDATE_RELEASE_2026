"""Tests for the SOC command centre page."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QWidget

from ui.backend import (
    BackendClient,
    CampaignSummaryDTO,
    HealthComponentDTO,
    IncidentSummaryDTO,
    MetricDTO,
    SocOverviewDTO,
    TimelineEventDTO,
)
from ui.context import UIContext
from ui.navigation import Route
from ui.pages.dashboard import DashboardPage
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def _context(navigate: object = None) -> UIContext:
    return UIContext(
        theme_manager=ThemeManager(ThemeMode.DARK),
        backend_client=BackendClient("http://127.0.0.1:9"),
        navigate=navigate,  # type: ignore[arg-type]
    )


def _overview() -> SocOverviewDTO:
    return SocOverviewDTO(
        threat_level="Critical",
        risk_score=0.97,
        platform_status="Operational",
        generated_at="2026-07-23T10:21:48+00:00",
        posture=(
            MetricDTO("Threat level", "Critical", tone="danger"),
            MetricDTO("Open incidents", "3", tone="danger"),
            MetricDTO("Active campaigns", "2", tone="warning"),
            MetricDTO("Platform", "Operational", tone="success"),
        ),
        incident_metrics=(MetricDTO("Open", "3"), MetricDTO("Critical", "1")),
        incident_queue=(
            IncidentSummaryDTO(
                id="i1",
                title="Brand Impersonation - Invoice overdue",
                category="brand_impersonation",
                risk_percent=84,
                status="investigating",
                priority="critical",
                assignee="alice",
                occurrences=3,
                affected_users=3,
                last_seen="2026-07-23T10:21:48",
            ),
        ),
        priority_distribution=(("critical", 1), ("high", 2)),
        campaign_metrics=(MetricDTO("Active campaigns", "2", tone="warning"),),
        campaigns=(
            CampaignSummaryDTO(
                id="c1",
                name="Brand Impersonation: Invoice Overdue",
                category="brand_impersonation",
                risk_percent=84,
                occurrences=3,
                affected_users=3,
                first_seen="2026-07-23T10:21:48",
                last_seen="2026-07-23T10:22:00",
            ),
        ),
        threat_metrics=(MetricDTO("Blacklisted artifacts", "4"),),
        top_malicious_senders=(("no-reply@pp-secure.xyz", 3),),
        top_malicious_urls=(("http://bit.ly/x", 2),),
        threat_categories=(("credential_harvesting", 2),),
        artifact_distribution=(("email", 3), ("url", 1)),
        timeline=(
            TimelineEventDTO(
                timestamp="2026-07-23T10:21:48",
                kind="email_analysis",
                severity="critical",
                title="Email analyzed",
                detail="bad@evil.xyz - Invoice overdue (phishing)",
                artifact_type="email",
            ),
        ),
        analytics=(MetricDTO("Artifacts analyzed", "6"),),
        risk_distribution=(("Critical", 4), ("Low", 2)),
        detection_trend=(("17 Jul", 0), ("23 Jul", 4)),
        analyst_activity=(MetricDTO("Assigned incidents", "1"),),
        recent_comments=(("alice", "Triaging now."),),
        health=(HealthComponentDTO("database", "healthy", "ok"),),
    )


def _text(widget: QWidget) -> str:
    labels = list(widget.findChildren(QLabel))
    if isinstance(widget, QLabel):
        labels.append(widget)
    return " | ".join(label.text() for label in labels if label.text())


def test_dashboard_builds(qapp: QApplication) -> None:
    assert DashboardPage(_context()) is not None


def test_dashboard_renders_all_sections(qapp: QApplication) -> None:
    page = DashboardPage(_context())
    page._on_loaded(_overview())
    assert page._body is not None
    text = _text(page._body)
    for heading in (
        "Executive Security Overview",
        "Critical Incidents",
        "Campaign Overview",
        "Threat Timeline",
        "Threat Intelligence",
        "Security Analytics",
        "Platform Health",
        "Analyst Activity",
    ):
        assert heading in text
    assert page._level_badge.text() == "THREAT LEVEL: CRITICAL"


def test_sections_follow_soc_priority_order(qapp: QApplication) -> None:
    """The most decision-relevant information must be rendered first."""
    page = DashboardPage(_context())
    page._on_loaded(_overview())
    assert page._body is not None
    text = _text(page._body)
    order = [
        "Executive Security Overview",
        "Critical Incidents",
        "Campaign Overview",
        "Threat Timeline",
        "Threat Intelligence",
        "Security Analytics",
        "Platform Health",
        "Analyst Activity",
    ]
    positions = [text.index(heading) for heading in order]
    assert positions == sorted(positions)


def test_incident_cards_render_triage_fields(qapp: QApplication) -> None:
    page = DashboardPage(_context())
    page._on_loaded(_overview())
    assert page._body is not None
    text = _text(page._body)
    assert "Brand Impersonation - Invoice overdue" in text
    assert "alice" in text
    assert "CRITICAL" in text
    assert "INVESTIGATING" in text


def test_empty_platform_shows_professional_states(qapp: QApplication) -> None:
    page = DashboardPage(_context())
    page._on_loaded(
        SocOverviewDTO(
            threat_level="Normal",
            platform_status="Operational",
            generated_at="2026-07-23T10:00:00+00:00",
        )
    )
    assert page._body is not None
    text = _text(page._body)
    assert "No incidents detected" in text
    assert "No active campaigns" in text
    assert "No activity recorded" in text
    assert "No analyst notes yet" in text


def test_loading_state_shows_skeletons(qapp: QApplication) -> None:
    from ui.components.timeline import SkeletonPanel

    page = DashboardPage(_context())
    page._show_loading()
    assert page._body is not None
    assert "Loading operational picture" in _text(page._body)
    assert page._body.findChildren(SkeletonPanel)


def test_dashboard_shows_recovery_state_instead_of_raw_error(qapp: QApplication) -> None:
    """A raw connection error must never reach the analyst."""
    page = DashboardPage(_context())
    page._on_loaded(SocOverviewDTO(error="[Errno 111] Connection refused"))
    assert page._body is not None
    text = _text(page._body)
    assert "Waiting for the platform" in text
    assert "Errno 111" not in text
    assert page._level_badge.text() == "OFFLINE"


def test_dashboard_recovers_when_backend_returns(qapp: QApplication) -> None:
    page = DashboardPage(_context())
    page._on_loaded(SocOverviewDTO(error="[Errno 111] Connection refused"))
    page._on_loaded(_overview())
    assert page._body is not None
    assert "Critical Incidents" in _text(page._body)
    assert page._level_badge.text() == "THREAT LEVEL: CRITICAL"


def test_dashboard_drill_down_navigates(qapp: QApplication) -> None:
    routes: list[Route] = []
    page = DashboardPage(_context(navigate=routes.append))
    page._on_loaded(_overview())
    page._context.go_to(Route.INCIDENTS)
    assert routes == [Route.INCIDENTS]


def test_context_without_navigation_is_a_no_op(qapp: QApplication) -> None:
    _context().go_to(Route.INCIDENTS)


def test_status_bar_summarises_operations(qapp: QApplication) -> None:
    """The status strip must communicate platform state at a glance."""
    page = DashboardPage(_context())
    page._on_loaded(_overview())
    assert page._level_badge.text() == "THREAT LEVEL: CRITICAL"
    assert page._status_badges["incidents"].text() == "INCIDENTS 3"
    assert page._status_badges["campaigns"].text() == "CAMPAIGNS 2"
    assert page._status_badges["platform"].text() == "PLATFORM OPERATIONAL"
    assert page._status_badges["backend"].text() == "BACKEND ONLINE"
    assert "AUTO-REFRESH" in page._auto_refresh.text()


def test_status_bar_reports_backend_loss(qapp: QApplication) -> None:
    page = DashboardPage(_context())
    page._on_loaded(SocOverviewDTO(error="[Errno 111] Connection refused"))
    assert page._status_badges["backend"].text() == "BACKEND UNREACHABLE"
    assert page._level_badge.text() == "OFFLINE"


def test_quick_actions_navigate(qapp: QApplication) -> None:
    from PySide6.QtWidgets import QPushButton

    routes: list[Route] = []
    page = DashboardPage(_context(navigate=routes.append))
    page._on_loaded(_overview())
    assert page._body is not None
    buttons = {b.text(): b for b in page._body.findChildren(QPushButton)}
    assert "Investigate critical incident" in buttons
    assert "Threat intelligence" in buttons
    buttons["Threat intelligence"].click()
    assert routes == [Route.THREAT_INTEL]


def test_incident_card_click_opens_investigation(qapp: QApplication) -> None:
    from ui.components.soc_cards import IncidentCard

    routes: list[Route] = []
    page = DashboardPage(_context(navigate=routes.append))
    page._on_loaded(_overview())
    assert page._body is not None
    cards = page._body.findChildren(IncidentCard)
    assert cards
    cards[0].clicked.emit()
    assert routes == [Route.INCIDENTS]


def test_health_tiles_label_unreported_diagnostics(qapp: QApplication) -> None:
    from ui.components.tiles import NOT_REPORTED

    page = DashboardPage(_context())
    page._on_loaded(_overview())
    assert page._body is not None
    assert NOT_REPORTED in _text(page._body)


def test_status_badges_fall_back_when_metric_absent(qapp: QApplication) -> None:
    """A missing metric must render a placeholder, never a wrong number."""
    page = DashboardPage(_context())
    page._on_loaded(
        SocOverviewDTO(
            threat_level="Normal",
            platform_status="Operational",
            generated_at="2026-07-24T10:00:00+00:00",
        )
    )
    assert page._status_badges["incidents"].text() == "INCIDENTS \u2014"


def test_dashboard_renders_advanced_analytics(qapp: QApplication) -> None:
    from core.domain.attack_view import InfrastructureCluster
    from core.domain.intelligence_view import (
        CampaignIntelligence,
        IOCIntelligence,
        ThreatScore,
    )
    from core.domain.recommendation_view import Recommendation
    from core.domain.soc_analytics_view import AnalyticsOverview

    page = DashboardPage(_context())
    overview = AnalyticsOverview(
        threat_priorities=(
            ThreatScore(
                artifact_id="url-1",
                label="evil.example",
                severity=0.9,
                confidence=0.7,
                exposure=0.5,
                blast_radius=3,
                priority=0.72,
                analyst_urgency=0.8,
                rationale=("high risk",),
            ),
        ),
        emerging_campaigns=(
            CampaignIntelligence(campaign_id="camp-1", label="Camp", artifact_count=4, ioc_count=2),
        ),
        ioc_trends=(IOCIntelligence(ioc_id="ioc-9", label="ioc-9", frequency=3, confidence=0.6),),
        infrastructure_reuse=(
            InfrastructureCluster(
                infra_id="ioc-9", infra_label="ioc-9", member_ids=("url-1", "file-1")
            ),
        ),
        threat_distribution=(("critical", 1), ("high", 0), ("medium", 0), ("low", 2)),
        recommendations=(
            Recommendation(
                kind="next_investigation",
                title="Investigate url-1",
                subject_id="url-1",
                priority=0.8,
                rationale=("highest urgency",),
            ),
        ),
    )
    page._on_analytics(overview)
    text = _text(page._advanced)
    for heading in (
        "Advanced Threat Analytics",
        "Threat priorities",
        "Analyst recommendations",
        "Threat distribution",
        "Infrastructure reuse",
        "Emerging campaigns",
        "IOC trends",
    ):
        assert heading in text
    assert "Investigate url-1" in text

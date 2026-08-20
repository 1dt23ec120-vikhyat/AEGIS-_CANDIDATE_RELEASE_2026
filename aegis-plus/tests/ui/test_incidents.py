"""Tests for the incidents investigation page."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QWidget

from ui.backend import ArtifactDTO, BackendClient, CampaignDTO, IncidentDTO, IncidentEventDTO
from ui.context import UIContext
from ui.pages.incidents import IncidentsPage
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def _context() -> UIContext:
    return UIContext(
        theme_manager=ThemeManager(ThemeMode.DARK),
        backend_client=BackendClient("http://127.0.0.1:9"),
    )


def _incident() -> IncidentDTO:
    return IncidentDTO(
        id="inc-1",
        title="Credential Harvesting - Verify your account",
        category="credential_harvesting",
        risk_percent=88,
        status="investigating",
        priority="critical",
        assignee="alice",
        tags=("phishing",),
        campaign_id="camp-1",
        scan_ids=("s1", "s2"),
        occurrences=2,
        affected_users=("one@corp.com", "two@corp.com"),
        artifacts=(
            ArtifactDTO("sender", "no-reply@pp-secure.xyz", "Sender: no-reply@pp-secure.xyz"),
            ArtifactDTO("url", "http://bit.ly/x", "Url: http://bit.ly/x"),
        ),
        events=(
            IncidentEventDTO("Incident created", "Opened from detection", "2026-07-23T09:00:00"),
            IncidentEventDTO("Detection correlated", "Shared sender", "2026-07-23T09:05:00"),
        ),
        first_seen="2026-07-23T09:00:00",
        last_seen="2026-07-23T09:05:00",
    )


def _campaign() -> CampaignDTO:
    return CampaignDTO(
        id="camp-1",
        name="Credential Harvesting: Invoice Overdue",
        category="credential_harvesting",
        risk_percent=88,
        occurrences=2,
        affected_users=("one@corp.com", "two@corp.com"),
        first_seen="2026-07-23T09:00:00",
        last_seen="2026-07-23T09:05:00",
    )


def _text(widget: QWidget) -> str:
    return " | ".join(c.text() for c in widget.findChildren(QLabel) if c.text())


def test_incidents_page_builds(qapp: QApplication) -> None:
    assert IncidentsPage(_context()) is not None


def test_incidents_page_renders_queue_and_detail(qapp: QApplication) -> None:
    page = IncidentsPage(_context())
    page._on_loaded(([_incident()], [_campaign()]))
    assert page._table.rowCount() == 1
    assert page._campaign_table.rowCount() == 1
    assert page._detail_body is not None
    text = _text(page._detail_body)
    for heading in (
        "Campaign",
        "Correlated Evidence",
        "Affected Users",
        "Timeline",
        "Analyst Workflow",
    ):
        assert heading in text


def test_incidents_page_handles_empty_queue(qapp: QApplication) -> None:
    page = IncidentsPage(_context())
    page._on_loaded(([], []))
    assert page._table.rowCount() == 0

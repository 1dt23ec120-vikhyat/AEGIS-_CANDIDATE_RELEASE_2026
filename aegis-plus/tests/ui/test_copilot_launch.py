"""Tests for the "Ask Copilot" launch points (M12 Phase 2).

Each investigation surface — URL, email, file, incident, Graph Explorer, and the
SOC dashboard — offers an "Ask Copilot" action that navigates to the Copilot
route with the correct focus payload. These tests drive each page's action
handler with a fake navigate callback and assert the payload, reusing the
existing routing framework.
"""

from __future__ import annotations

import pytest

from ui.backend import BackendClient, EmailScanResult, FileScanResult, IncidentDTO, ScanResult
from ui.context import UIContext
from ui.navigation.routes import Route
from ui.pages.dashboard import DashboardPage
from ui.pages.email_scanner import EmailScannerPage
from ui.pages.file_scanner import FileScannerPage
from ui.pages.incidents import IncidentsPage
from ui.pages.url_scanner import UrlScannerPage
from ui.theme import ThemeManager

pytestmark = pytest.mark.ui


class _Nav:
    def __init__(self) -> None:
        self.calls: list[tuple[object, dict[str, object]]] = []

    def __call__(self, route: object, payload: object = None) -> None:
        assert isinstance(payload, dict)
        self.calls.append((route, payload))


def _context(nav: _Nav) -> UIContext:
    return UIContext(
        theme_manager=ThemeManager(),
        backend_client=BackendClient("http://127.0.0.1:9"),
        navigate=nav,
    )


def test_url_scanner_asks_copilot_with_url(qapp: object) -> None:
    nav = _Nav()
    page = UrlScannerPage(_context(nav))
    page._on_completed(ScanResult(url="http://evil.example", verdict="phishing"))
    assert not page._copilot_action.isHidden()
    page._ask_copilot()
    route, payload = nav.calls[0]
    assert route is Route.COPILOT
    assert isinstance(payload, dict)
    assert payload["focus"] == "http://evil.example"
    assert payload["kind"] == "artifact"
    assert payload["origin"] is Route.URL_SCANNER


def test_file_scanner_asks_copilot_with_sha256(qapp: object) -> None:
    nav = _Nav()
    page = FileScannerPage(_context(nav))
    page._on_completed(FileScanResult(filename="x.docm", sha256="abc123", verdict="malicious"))
    page._ask_copilot()
    route, payload = nav.calls[0]
    assert route is Route.COPILOT
    assert payload["focus"] == "abc123"
    assert payload["origin"] is Route.FILE_SCANNER


def test_email_scanner_prefers_incident_focus(qapp: object) -> None:
    nav = _Nav()
    page = EmailScannerPage(_context(nav))
    page._on_completed(
        EmailScanResult(sender="bad@evil.example", incident_id="inc-9", verdict="phishing")
    )
    page._ask_copilot()
    _, payload = nav.calls[0]
    assert payload["focus"] == "inc-9"
    assert payload["kind"] == "incident"


def test_email_scanner_falls_back_to_sender(qapp: object) -> None:
    nav = _Nav()
    page = EmailScannerPage(_context(nav))
    page._on_completed(EmailScanResult(sender="bad@evil.example", verdict="phishing"))
    page._ask_copilot()
    _, payload = nav.calls[0]
    assert payload["focus"] == "bad@evil.example"
    assert payload["kind"] == "artifact"


def test_incident_page_asks_copilot_with_incident(qapp: object) -> None:
    nav = _Nav()
    page = IncidentsPage(_context(nav))
    page._select(IncidentDTO(id="inc-1", title="Phishing wave"))
    assert page._copilot_action.isEnabled()
    page._ask_copilot()
    route, payload = nav.calls[0]
    assert route is Route.COPILOT
    assert payload["focus"] == "inc-1"
    assert payload["kind"] == "incident"


def test_dashboard_asks_copilot_global(qapp: object) -> None:
    nav = _Nav()
    page = DashboardPage(_context(nav))
    page._ask_copilot()
    route, payload = nav.calls[0]
    assert route is Route.COPILOT
    assert payload["kind"] == "global"
    assert payload["origin"] is Route.DASHBOARD


def test_url_scanner_action_hidden_on_error(qapp: object) -> None:
    nav = _Nav()
    page = UrlScannerPage(_context(nav))
    page._on_completed(ScanResult(error="bad input"))
    assert page._copilot_action.isHidden()

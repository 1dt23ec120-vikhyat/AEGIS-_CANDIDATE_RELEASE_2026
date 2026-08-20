"""Tests for the Threat Intelligence page and warning dialog."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication, QWidget

from ui.backend import BackendClient, Contribution, ScanResult, ThreatEntryDTO
from ui.components.threat_dialog import ThreatWarningDialog
from ui.context import UIContext
from ui.pages.threat_intelligence import ThreatIntelligencePage
from ui.pages.url_scanner import UrlScannerPage
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def _context() -> UIContext:
    return UIContext(
        theme_manager=ThemeManager(ThemeMode.DARK),
        backend_client=BackendClient("http://127.0.0.1:9"),
    )


def _threat() -> ThreatEntryDTO:
    return ThreatEntryDTO(
        hash="abc123",
        url="http://bad.example/login",
        artifact_type="url",
        verdict="phishing",
        risk_percent=80,
        confidence=0.6,
        first_detected="2026-07-20T10:00:00+00:00",
        last_detected="2026-07-20T12:00:00+00:00",
        detection_count=3,
        blocked=True,
        block_source="ai",
        indicators=(Contribution("ip_address_used", "Host is an IP", 0.0),),
    )


def test_threat_page_builds(qapp: QApplication) -> None:
    page = ThreatIntelligencePage(_context())
    assert page is not None


def test_threat_page_detail_renders(qapp: QApplication) -> None:
    page = ThreatIntelligencePage(_context())
    page._show_detail(_threat())
    assert not page._detail.isHidden()


def test_warning_dialog_builds(qapp: QApplication) -> None:
    dialog = ThreatWarningDialog(_threat(), ThemeManager(ThemeMode.DARK))
    assert isinstance(dialog, QWidget)
    assert dialog.isModal()


def test_scanner_shows_blacklisted_state(qapp: QApplication) -> None:
    page = UrlScannerPage(_context())
    result = ScanResult(
        url="http://bad.example",
        verdict="phishing",
        risk_percent=80,
        confidence=0.6,
        blacklisted=True,
        blacklist_hit=True,
        contributions=(Contribution("ip_address_used", "Host is an IP", 0.3),),
    )
    assert isinstance(page._build_result(result), QWidget)

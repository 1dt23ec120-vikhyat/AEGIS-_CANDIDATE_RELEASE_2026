"""Tests for the URL scanner page and scan result parsing."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication, QWidget

from ui.backend import BackendClient, Contribution, ScanResult
from ui.backend.client import _parse_scan
from ui.context import UIContext
from ui.pages.url_scanner import UrlScannerPage
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def _context() -> UIContext:
    return UIContext(
        theme_manager=ThemeManager(ThemeMode.DARK),
        backend_client=BackendClient("http://127.0.0.1:9"),
    )


def test_parse_scan_builds_result() -> None:
    result = _parse_scan(
        {
            "id": "abc",
            "url": "http://x",
            "verdict": "phishing",
            "threat_score": 0.8,
            "confidence": 0.9,
            "risk_percent": 80,
            "contributions": [{"feature": "f", "detail": "d", "weight": 0.3}],
        }
    )
    assert result.ok
    assert result.verdict == "phishing"
    assert result.contributions[0].feature == "f"


def test_scanner_page_builds(qapp: QApplication) -> None:
    page = UrlScannerPage(_context())
    assert page is not None


def test_result_rendering_success_and_error(qapp: QApplication) -> None:
    page = UrlScannerPage(_context())

    ok = ScanResult(
        url="http://x",
        verdict="phishing",
        threat_score=0.8,
        confidence=0.9,
        risk_percent=80,
        contributions=(Contribution("ip_address_used", "Host is an IP", 0.3),),
    )
    assert isinstance(page._build_result(ok), QWidget)

    err = ScanResult(error="boom")
    assert isinstance(page._build_result(err), QWidget)

"""Tests for the email scanner page and email-scan parsing."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication

from ui.backend import BackendClient, EmailScanResult, EmbeddedUrlDTO
from ui.backend.client import _parse_email_scan
from ui.context import UIContext
from ui.pages.email_scanner import EmailScannerPage
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def _context() -> UIContext:
    return UIContext(
        theme_manager=ThemeManager(ThemeMode.DARK),
        backend_client=BackendClient("http://127.0.0.1:9"),
    )


def test_parse_email_scan_builds_result() -> None:
    result = _parse_email_scan(
        {
            "id": "abc",
            "sender": "a@b.com",
            "subject": "hi",
            "verdict": "phishing",
            "category": "credential_harvesting",
            "threat_score": 0.9,
            "confidence": 0.8,
            "risk_percent": 90,
            "evidence_strength": 0.6,
            "malicious": True,
            "url_count": 1,
            "malicious_url_count": 1,
            "contributions": [{"feature": "f", "detail": "d", "weight": 0.5}],
            "sources": [
                {
                    "source": "url",
                    "risk_percent": 100,
                    "confidence": 0.9,
                    "available": True,
                    "rationale": "r",
                }
            ],
            "urls": [
                {"url": "http://x", "verdict": "phishing", "risk_percent": 100, "blacklisted": True}
            ],
        }
    )
    assert result.ok
    assert result.malicious
    assert result.urls[0].blacklisted


def test_email_scanner_page_builds(qapp: QApplication) -> None:
    page = EmailScannerPage(_context())
    assert page is not None


def test_email_scanner_renders_result(qapp: QApplication) -> None:
    page = EmailScannerPage(_context())
    result = EmailScanResult(
        sender="a@b.com",
        subject="hi",
        verdict="phishing",
        category="phishing",
        risk_percent=90,
        malicious=True,
        url_count=1,
        malicious_url_count=1,
        urls=(EmbeddedUrlDTO("http://x", "phishing", 100, True),),
    )
    page._on_completed(result)
    assert page._body is not None


def _rich_result() -> EmailScanResult:
    from ui.backend import (
        AttachmentDTO,
        AuthMechanismDTO,
        BodyDTO,
        Contribution,
        OverviewDTO,
        SenderIntelDTO,
        SourceScoreDTO,
    )

    return EmailScanResult(
        sender="ceo@company-invoices.xyz",
        subject="Urgent wire transfer",
        verdict="phishing",
        category="business_email_compromise",
        threat_score=0.88,
        confidence=0.84,
        risk_percent=88,
        evidence_strength=0.6,
        malicious=True,
        url_count=1,
        malicious_url_count=1,
        contributions=(Contribution("bec_language", "Contains BEC cues", 0.5),),
        sources=(SourceScoreDTO("sender", 60, 0.75, True, "Sender analysis"),),
        urls=(EmbeddedUrlDTO("http://evil.example", "phishing", 100, True),),
        authentication=(
            AuthMechanismDTO("SPF", "fail", "SPF did not pass", "Confirms the server."),
            AuthMechanismDTO("DKIM", "pass", "DKIM passed.", "Confirms signature."),
            AuthMechanismDTO("DMARC", "warning", "Not configured.", "Confirms alignment."),
        ),
        overview=OverviewDTO(
            from_display="CEO",
            from_address="ceo@company-invoices.xyz",
            to=("analyst@example.com",),
            cc=("manager@example.com",),
            subject="Urgent wire transfer",
            message_id="<inv-1@x>",
        ),
        sender_intel=SenderIntelDTO(
            display_name="CEO",
            address="ceo@company-invoices.xyz",
            domain="company-invoices.xyz",
            reply_to="finance@evil.example",
            reply_to_mismatch=True,
            prior_scans=2,
            prior_malicious=1,
        ),
        attachments=(
            AttachmentDTO(
                filename="details.pdf.exe",
                extension=".exe",
                size=64,
                content_type="application/octet-stream",
                sha256="a" * 64,
                indicators=("Executable/dangerous extension",),
            ),
        ),
        body=BodyDTO(plain="Please process this payment.", html="", raw="From: ..."),
        scan_id="",
    )


def test_workspace_renders_all_sections(qapp: QApplication) -> None:
    page = EmailScannerPage(_context())
    page._on_completed(_rich_result())
    assert page._body is not None
    text = _collect_text(page._body)
    for heading in (
        "Email Overview",
        "Authentication",
        "Sender Intelligence",
        "Threat Intelligence",
        "Embedded URLs",
        "Attachments",
        "Timeline",
        "Explainable AI",
        "Analyst Notes",
    ):
        assert heading in text


def test_sections_are_collapsible(qapp: QApplication) -> None:
    from ui.components.section import Section

    section = Section("Demo", expanded=True)
    assert section.is_expanded()
    section.set_expanded(False)
    assert not section.is_expanded()


def _collect_text(widget: object) -> str:
    from PySide6.QtWidgets import QLabel, QWidget

    assert isinstance(widget, QWidget)
    return " | ".join(child.text() for child in widget.findChildren(QLabel) if child.text())

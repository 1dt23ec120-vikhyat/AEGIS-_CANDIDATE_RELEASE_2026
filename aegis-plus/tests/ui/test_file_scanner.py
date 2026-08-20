"""Tests for the file scanner page and file-scan parsing."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QTableWidget, QWidget

from application.api.file import _summary_model
from services.investigation import build_file_investigation
from ui.backend import BackendClient, FileScanResult
from ui.backend.client import _parse_file_scan
from ui.context import UIContext
from ui.pages.file_scanner import FileScannerPage
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def _context() -> UIContext:
    return UIContext(
        theme_manager=ThemeManager(ThemeMode.DARK),
        backend_client=BackendClient("http://127.0.0.1:9"),
    )


def _text(widget: QWidget) -> str:
    parts = [label.text() for label in widget.findChildren(QLabel) if label.text()]
    if isinstance(widget, QLabel):
        parts.append(widget.text())
    for table in widget.findChildren(QTableWidget):
        for row in range(table.rowCount()):
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item is not None and item.text():
                    parts.append(item.text())
    return " | ".join(parts)


_MALICIOUS = {
    "id": "scan-1",
    "filename": "invoice.docm",
    "verdict": "phishing",
    "category": "malicious_document",
    "threat_score": 0.8,
    "confidence": 0.8,
    "risk_percent": 80,
    "evidence_strength": 0.6,
    "malicious": True,
    "size": 2048,
    "sha256": "a" * 64,
    "file_kind": "document",
    "entropy": 4.98,
    "indicator_count": 2,
    "url_count": 1,
    "malicious_url_count": 0,
    "contributions": [
        {"feature": "macro_indicators", "detail": "Auto_Open detected", "weight": 0.8}
    ],
    "sources": [
        {
            "source": "file_script",
            "risk_percent": 80,
            "confidence": 0.8,
            "available": True,
            "rationale": "Macro analysis",
        }
    ],
    "urls": [
        {"url": "http://x.example", "verdict": "phishing", "risk_percent": 90, "blacklisted": True}
    ],
    "indicators": {
        "urls": ["http://x.example"],
        "domains": ["evil.example"],
        "ipv4_addresses": ["10.0.0.1"],
        "emails": ["a@b.com"],
        "hashes": [],
        "total": 4,
    },
    "overview": {
        "filename": "invoice.docm",
        "size": 2048,
        "sha256": "a" * 64,
        "sha1": "b" * 40,
        "md5": "c" * 32,
        "file_kind": "document",
        "detected_mime": "application/x-ole-storage",
        "declared_mime": "",
        "extension": ".docm",
        "entropy": 4.98,
        "entropy_descriptor": "moderate",
        "mime_mismatch": False,
        "double_extension": False,
        "is_executable": False,
        "is_script": False,
        "is_archive": False,
    },
    "incident_id": "inc-1",
    "incident_title": "Malicious Document - invoice.docm",
    "campaign_name": "Malicious Document: invoice.docm",
    "correlation_rationale": "New incident opened",
}


def _investigation_payload() -> dict[str, object]:
    """Reproduce the investigation summary the backend now embeds in the response.

    Built with the same service builder and API serializer the backend uses, so
    the fixture stays faithful to production output (the UI no longer constructs
    the summary itself).
    """
    summary = build_file_investigation(
        scan_id="scan-1",
        filename="invoice.docm",
        verdict="phishing",
        category="malicious_document",
        risk_percent=80,
        confidence=0.8,
        evidence_strength=0.6,
        malicious=True,
        size=2048,
        sha256="a" * 64,
        sha1="b" * 40,
        md5="c" * 32,
        file_kind="document",
        detected_mime="application/x-ole-storage",
        declared_mime="",
        extension=".docm",
        entropy=4.98,
        entropy_descriptor="moderate",
        is_executable=False,
        is_script=False,
        is_archive=False,
        mime_mismatch=False,
        double_extension=False,
        indicator_count=2,
        url_count=1,
        malicious_url_count=0,
        contributions=[
            SimpleNamespace(
                feature="macro_indicators",
                detail="Auto_Open detected",
                weight=0.8,
                technique_id="",
                recommendation="",
            )
        ],
        sources=[
            SimpleNamespace(
                source="file_script",
                risk_percent=80,
                confidence=0.8,
                available=True,
                rationale="Macro analysis",
            )
        ],
        urls=(),
        indicators=None,
        incident_id="inc-1",
        incident_title="Malicious Document - invoice.docm",
        campaign_name="Malicious Document: invoice.docm",
        correlation_rationale="New incident opened",
        provider_diagnostics=(("File Script", "1.0.0", 0.0, 1),),
    )
    return _summary_model(summary).model_dump()


_MALICIOUS["investigation"] = _investigation_payload()


def test_parse_file_scan_builds_result() -> None:
    result = _parse_file_scan(_MALICIOUS)
    assert result.ok
    assert result.malicious
    assert result.sha256 == "a" * 64
    assert result.scan_id == "scan-1"
    assert result.overview is not None
    assert result.overview.md5 == "c" * 32
    assert result.indicators is not None
    assert result.indicators.total == 4


def test_parse_file_scan_handles_missing_optionals() -> None:
    result = _parse_file_scan({"filename": "x", "verdict": "legitimate"})
    assert result.ok
    assert result.overview is None
    assert result.indicators is None


def test_file_scanner_starts_empty(qapp: QApplication) -> None:
    page = FileScannerPage(_context())
    assert page._body is not None
    assert "No investigation open" in _text(page._body)
    assert not page._button.isEnabled()


def test_file_scanner_renders_malicious_result(qapp: QApplication) -> None:
    page = FileScannerPage(_context())
    page._on_completed(_parse_file_scan(_MALICIOUS))
    assert page._body is not None
    text = _text(page._body)
    assert "PHISHING" in text
    assert "Malicious Document" in text
    assert "a" * 64 in text  # sha256
    # Unified workspace sections
    assert "Investigation Timeline" in text
    assert "Metadata" in text
    assert "Indicators of Compromise" in text
    assert "Analyst Recommendations" in text


def test_file_scanner_shows_correlation_when_present(qapp: QApplication) -> None:
    page = FileScannerPage(_context())
    page._on_completed(_parse_file_scan(_MALICIOUS))
    assert page._body is not None
    text = _text(page._body)
    assert "Malicious Document - invoice.docm" in text
    assert "Threat History" in text


def test_file_scanner_renders_error(qapp: QApplication) -> None:
    page = FileScannerPage(_context())
    page._on_completed(FileScanResult(error="Scan failed: boom"))
    assert page._body is not None
    assert "Investigation failed" in _text(page._body)


def test_file_scanner_reports_unavailable_mime_as_not_reported(qapp: QApplication) -> None:
    page = FileScannerPage(_context())
    page._on_completed(_parse_file_scan(_MALICIOUS))
    assert page._body is not None
    # declared_mime is empty -> shown as "Not reported" in metadata.
    assert "Not reported" in _text(page._body)


def test_unified_workspace_has_all_sections(qapp: QApplication) -> None:
    """The unified workspace should present every required section."""
    page = FileScannerPage(_context())
    page._on_completed(_parse_file_scan(_MALICIOUS))
    assert page._body is not None
    text = _text(page._body)
    for section in (
        "Investigation Timeline",
        "Evidence Tree",
        "Relationships",
        "IOC Workspace",
        "Indicators of Compromise",
        "Metadata",
        "Embedded URLs",
        "Threat History",
        "Provider Diagnostics",
        "Analyst Recommendations",
        "Performance",
        "Analyst Notes",
    ):
        assert section in text, f"Missing section: {section}"


def test_evidence_tree_shows_provider_nodes(qapp: QApplication) -> None:
    page = FileScannerPage(_context())
    page._on_completed(_parse_file_scan(_MALICIOUS))
    assert page._body is not None
    from PySide6.QtWidgets import QTreeWidget

    trees = page._body.findChildren(QTreeWidget)
    assert trees, "Evidence tree should be rendered"
    assert trees[0].topLevelItemCount() > 0


def test_file_scan_result_carries_investigation_summary() -> None:
    """The backend-built summary is reconstructed into the result DTO."""
    result = _parse_file_scan(_MALICIOUS)
    assert result.investigation is not None
    assert result.investigation.verdict == "phishing"
    assert result.investigation.evidence_tree  # provider nodes present
    assert any(field.value == "Not reported" for field in result.investigation.metadata)


def test_file_scan_result_without_investigation_is_safe() -> None:
    """A response lacking an investigation block yields ``None`` (no crash)."""
    result = _parse_file_scan({"filename": "x", "verdict": "legitimate"})
    assert result.investigation is None

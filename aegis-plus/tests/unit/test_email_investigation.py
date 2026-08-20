"""Tests for the email investigation domain and analyst workflow."""

from __future__ import annotations

from core.constants import InvestigationPriority, InvestigationStatus
from core.domain.email import AuthStatus, EmailMessage
from core.entities import EmailInvestigation

_FULL = (
    "From: PayPal Support <no-reply@paypal-secure.xyz>\n"
    "Reply-To: attacker@evil.example\n"
    "To: analyst@example.com, second@example.com\n"
    "Cc: manager@example.com\n"
    "Bcc: archive@example.com\n"
    "Subject: Urgent: verify your account\n"
    "Date: Tue, 21 Jul 2026 09:14:00 +0000\n"
    "Message-ID: <abc123@paypal-secure.xyz>\n"
    "MIME-Version: 1.0\n"
    "X-Priority: 1\n"
    "Authentication-Results: mx; spf=fail dkim=pass dmarc=none\n"
    "Content-Type: multipart/alternative; boundary=B\n\n"
    "--B\nContent-Type: text/plain\n\nVisit http://bit.ly/verify-now now\n"
    "--B\nContent-Type: text/html\n\n<p>Visit <a href='http://evil.example/go'>here</a></p>\n"
    "--B--\n"
)


def test_parse_extracts_full_metadata() -> None:
    email = EmailMessage.parse(_FULL)
    assert [a.address for a in email.recipients] == [
        "analyst@example.com",
        "second@example.com",
    ]
    assert [a.address for a in email.cc] == ["manager@example.com"]
    assert [a.address for a in email.bcc] == ["archive@example.com"]
    assert email.message_id == "<abc123@paypal-secure.xyz>"
    assert email.mime_version == "1.0"
    assert email.priority == "1"
    assert email.date.startswith("Tue, 21 Jul 2026")


def test_parse_collects_plain_and_html_bodies_and_all_urls() -> None:
    email = EmailMessage.parse(_FULL)
    assert "Visit http://bit.ly/verify-now" in email.body
    assert "<a href=" in email.html_body
    assert "http://bit.ly/verify-now" in email.urls
    assert "http://evil.example/go" in email.urls


def test_authentication_breakdown_reports_each_mechanism() -> None:
    email = EmailMessage.parse(_FULL)
    breakdown = {m.name: m for m in email.authentication_breakdown()}
    assert breakdown["SPF"].status is AuthStatus.FAIL
    assert breakdown["DKIM"].status is AuthStatus.PASS
    assert breakdown["DMARC"].status is AuthStatus.WARNING
    assert all(m.impact for m in breakdown.values())


def test_authentication_breakdown_when_absent() -> None:
    email = EmailMessage.parse("From: a@b.com\nSubject: hi\n\nbody\n")
    assert all(m.status is AuthStatus.NONE for m in email.authentication_breakdown())


def test_attachment_risk_indicators() -> None:
    raw = (
        "From: a@b.com\nSubject: doc\n"
        "Content-Type: multipart/mixed; boundary=B\n\n"
        "--B\nContent-Type: text/plain\n\nbody\n"
        "--B\n"
        'Content-Type: application/octet-stream; name="invoice.pdf.exe"\n'
        'Content-Disposition: attachment; filename="invoice.pdf.exe"\n\nXX\n'
        "--B--\n"
    )
    attachment = EmailMessage.parse(raw).attachments[0]
    assert attachment.is_dangerous
    assert attachment.has_double_extension
    assert "Executable/dangerous extension" in attachment.risk_indicators
    assert "Deceptive double extension" in attachment.risk_indicators


def test_investigation_defaults_to_open() -> None:
    assert EmailInvestigation(scan_id="scan-1").status is InvestigationStatus.OPEN


def test_investigation_update_changes_state() -> None:
    investigation = EmailInvestigation(scan_id="scan-1")
    investigation.update(
        status=InvestigationStatus.CONFIRMED_THREAT,
        priority=InvestigationPriority.CRITICAL,
        tags=("bec", "finance"),
        notes="Escalated to IR.",
    )
    assert investigation.status is InvestigationStatus.CONFIRMED_THREAT
    assert investigation.priority is InvestigationPriority.CRITICAL
    assert investigation.tags == ("bec", "finance")
    assert investigation.notes == "Escalated to IR."

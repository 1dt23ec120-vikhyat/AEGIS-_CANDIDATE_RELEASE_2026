"""Tests for the email evidence providers."""

from __future__ import annotations

from ai.email_analysis import (
    AttachmentProvider,
    AuthenticationProvider,
    HeaderAnalysisProvider,
    LanguageProvider,
    SenderReputationProvider,
)
from core.domain.analysis import Verdict
from core.domain.email import EmailMessage
from core.domain.intelligence import EvidenceSource, ThreatCategory


def _email(raw: str) -> EmailMessage:
    return EmailMessage.parse(raw)


def test_header_provider_flags_reply_to_mismatch() -> None:
    email = _email(
        "From: Acme <billing@acme.com>\n"
        "Reply-To: attacker@evil.example\n"
        "Subject: hi\n\nbody\n"
    )
    evidence = HeaderAnalysisProvider().assess(email)
    assert evidence.source is EvidenceSource.HEADER
    assert evidence.risk > 0.0
    assert any(c.feature == "reply_to_mismatch" and c.triggered for c in evidence.contributions)


def test_authentication_provider_flags_spf_dkim_dmarc_failures() -> None:
    email = _email(
        "From: bank@chase.com\n"
        "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"
        "Subject: hi\n\nbody\n"
    )
    evidence = AuthenticationProvider().assess(email)
    assert evidence.source is EvidenceSource.AUTHENTICATION
    assert evidence.risk > 0.5
    assert evidence.confidence >= 0.85


def test_authentication_provider_is_category_neutral() -> None:
    """Auth failures contribute risk but must not claim the primary category.

    The threat's nature (BEC, credential harvesting, brand impersonation) is
    determined by the sender, language, attachment, and URL providers.
    """
    email = _email(
        "From: bank@chase.com\n"
        "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"
        "Subject: hi\n\nbody\n"
    )
    evidence = AuthenticationProvider().assess(email)
    assert evidence.risk > 0.0
    assert evidence.category is ThreatCategory.NONE


def test_authentication_provider_low_confidence_when_absent() -> None:
    email = _email("From: a@b.com\nSubject: hi\n\nbody\n")
    evidence = AuthenticationProvider().assess(email)
    assert evidence.risk == 0.0
    assert evidence.confidence < 0.5


def test_sender_provider_detects_brand_impersonation() -> None:
    email = _email("From: PayPal Service <no-reply@secure-paypal.xyz>\nSubject: hi\n\nbody\n")
    evidence = SenderReputationProvider().assess(email)
    assert evidence.category is ThreatCategory.BRAND_IMPERSONATION
    assert evidence.risk > 0.0
    assert any(c.feature == "brand_impersonation" and c.triggered for c in evidence.contributions)


def test_language_provider_categorizes_credential_harvesting() -> None:
    email = _email(
        "From: a@b.com\nSubject: Action required\n\n"
        "Your account is suspended. Click here to verify and reset your password.\n"
    )
    evidence = LanguageProvider().assess(email)
    assert evidence.category is ThreatCategory.CREDENTIAL_HARVESTING
    assert evidence.risk > 0.0


def test_language_provider_categorizes_bec() -> None:
    email = _email(
        "From: ceo@company.com\nSubject: Quick task\n\n"
        "Are you available? I need you to process this payment via wire transfer.\n"
    )
    evidence = LanguageProvider().assess(email)
    assert evidence.category is ThreatCategory.BUSINESS_EMAIL_COMPROMISE


def test_attachment_provider_flags_dangerous_and_double_extension() -> None:
    raw = (
        "From: a@b.com\nSubject: invoice\n"
        "Content-Type: multipart/mixed; boundary=B\n\n"
        "--B\nContent-Type: text/plain\n\nsee attached\n"
        "--B\n"
        'Content-Type: application/octet-stream; name="invoice.pdf.exe"\n'
        'Content-Disposition: attachment; filename="invoice.pdf.exe"\n\nX\n'
        "--B--\n"
    )
    evidence = AttachmentProvider().assess(_email(raw))
    assert evidence.category is ThreatCategory.MALWARE_DELIVERY
    assert evidence.risk > 0.0
    triggered = {c.feature for c in evidence.contributions if c.triggered}
    assert "dangerous_attachment" in triggered
    assert "double_extension" in triggered


def test_attachment_provider_clean_when_no_attachments() -> None:
    evidence = AttachmentProvider().assess(_email("From: a@b.com\nSubject: hi\n\nbody\n"))
    assert evidence.risk == 0.0
    assert evidence.available


def test_malicious_verdict_always_carries_a_category() -> None:
    """Auth-only risk must not yield a malicious verdict with category 'none'."""
    from ai.email_analysis import HybridEmailAnalyzer

    analyzer = HybridEmailAnalyzer(
        [AuthenticationProvider()],
        weights={EvidenceSource.AUTHENTICATION: 1.3},
        suspicious_threshold=0.35,
        phishing_threshold=0.65,
    )
    report = analyzer.analyze(
        _email(
            "From: someone@example.com\n"
            "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"
            "Subject: hello\n\nnothing suspicious in the text\n"
        )
    )
    assert report.verdict is not Verdict.LEGITIMATE
    assert report.primary_category is ThreatCategory.SUSPICIOUS_SENDER

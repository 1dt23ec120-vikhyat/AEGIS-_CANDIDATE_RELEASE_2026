"""Tests for the email domain model."""

from __future__ import annotations

import pytest

from core.domain.email import EmailAddress, EmailMessage
from core.exceptions import ValidationError

_MULTIPART = (
    "From: Acme Support <support@acme-secure.xyz>\n"
    "Reply-To: attacker@evil.example\n"
    "To: you@example.com\n"
    "Subject: Urgent: verify your account\n"
    "Authentication-Results: mx.example; spf=fail dkim=fail dmarc=fail\n"
    "Content-Type: multipart/mixed; boundary=BOUND\n\n"
    "--BOUND\n"
    "Content-Type: text/plain\n\n"
    "Please verify at http://bit.ly/verify-now and also https://acme-secure.xyz/login\n"
    "--BOUND\n"
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"\n'
    'Content-Disposition: attachment; filename="invoice.pdf.exe"\n\n'
    "payload-bytes\n"
    "--BOUND--\n"
)


def test_parse_extracts_core_fields() -> None:
    email = EmailMessage.parse(_MULTIPART)
    assert email.sender.address == "support@acme-secure.xyz"
    assert email.sender.display_name == "Acme Support"
    assert email.reply_to is not None
    assert email.reply_to.domain == "evil.example"
    assert email.subject == "Urgent: verify your account"
    assert "spf=fail" in email.authentication_results


def test_parse_extracts_urls_deduplicated_and_ordered() -> None:
    email = EmailMessage.parse(_MULTIPART)
    assert email.urls == (
        "http://bit.ly/verify-now",
        "https://acme-secure.xyz/login",
    )


def test_parse_extracts_attachment_metadata() -> None:
    email = EmailMessage.parse(_MULTIPART)
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.filename == "invoice.pdf.exe"
    assert attachment.extension == ".exe"
    assert attachment.size > 0
    assert len(attachment.sha256) == 64


def test_fingerprint_is_stable_and_identity_readable() -> None:
    email = EmailMessage.parse(_MULTIPART)
    assert email.fingerprint == EmailMessage.parse(_MULTIPART).fingerprint
    assert email.sender.address in email.identity
    assert email.subject in email.identity


def test_parse_rejects_empty() -> None:
    with pytest.raises(ValidationError):
        EmailMessage.parse("   ")


def test_email_address_parse_handles_bare_address() -> None:
    address = EmailAddress.parse("plain@example.com")
    assert address.address == "plain@example.com"
    assert address.domain == "example.com"
    assert address.is_present

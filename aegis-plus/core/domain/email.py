"""Email domain model.

Framework-independent value objects for email analysis: an :class:`EmailAddress`,
an :class:`EmailAttachment` (metadata only), and an :class:`EmailMessage` that
parses a raw RFC-822 message into structured fields using only the standard
library. Parsing lives in the domain factory so services stay free of format
concerns; Domain Purity is preserved (stdlib only).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from email import message_from_string
from email.message import Message
from email.utils import getaddresses, parseaddr
from enum import Enum

from core.exceptions import ValidationError

_URL_PATTERN = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)
_MAX_RAW_LENGTH = 1_000_000


class AuthStatus(str, Enum):
    """The outcome of an email-authentication mechanism."""

    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class AuthMechanism:
    """A single authentication mechanism result (SPF, DKIM, or DMARC)."""

    name: str
    status: AuthStatus
    reason: str
    impact: str


_AUTH_IMPACT = {
    "spf": "Confirms the sending server is authorized for the domain.",
    "dkim": "Confirms the message was signed by the domain and not altered.",
    "dmarc": "Confirms alignment and enforces the domain's handling policy.",
}
_AUTH_FAIL_TOKENS = ("fail", "softfail", "temperror", "permerror")

DANGEROUS_EXTENSIONS = frozenset(
    {".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".com", ".pif", ".hta"}
)
MACRO_EXTENSIONS = frozenset({".docm", ".xlsm", ".pptm"})
ARCHIVE_EXTENSIONS = frozenset({".zip", ".rar", ".7z", ".iso", ".img"})
_DOUBLE_EXTENSION_PARTS = 2


@dataclass(frozen=True, slots=True)
class EmailAddress:
    """A parsed email address with optional display name."""

    display_name: str
    address: str

    @classmethod
    def parse(cls, raw: str) -> EmailAddress:
        """Parse a header value like ``"Acme <no-reply@acme.com>"``."""
        display, address = parseaddr(raw or "")
        return cls(display_name=display.strip(), address=address.strip().lower())

    @property
    def domain(self) -> str:
        """The domain part of the address, or empty if absent."""
        _, _, domain = self.address.partition("@")
        return domain

    @property
    def is_present(self) -> bool:
        """Whether an address was actually parsed."""
        return "@" in self.address


@dataclass(frozen=True, slots=True)
class EmailAttachment:
    """Attachment metadata (no content is retained)."""

    filename: str
    content_type: str
    size: int
    sha256: str

    @property
    def extension(self) -> str:
        """The lower-case file extension including the dot, or empty."""
        _, dot, ext = self.filename.rpartition(".")
        return f".{ext.lower()}" if dot else ""

    @property
    def has_double_extension(self) -> bool:
        """Whether the filename uses a deceptive double extension."""
        return self.filename.count(".") >= _DOUBLE_EXTENSION_PARTS

    @property
    def is_dangerous(self) -> bool:
        """Whether the attachment carries an executable/dangerous extension."""
        return self.extension in DANGEROUS_EXTENSIONS

    @property
    def risk_indicators(self) -> tuple[str, ...]:
        """Human-readable risk indicators derived from the metadata."""
        indicators: list[str] = []
        if self.is_dangerous:
            indicators.append("Executable/dangerous extension")
        if self.extension in MACRO_EXTENSIONS:
            indicators.append("Macro-enabled Office document")
        if self.extension in ARCHIVE_EXTENSIONS:
            indicators.append("Archive may conceal a payload")
        if self.has_double_extension:
            indicators.append("Deceptive double extension")
        return tuple(indicators)


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """A parsed email message."""

    raw: str
    sender: EmailAddress
    reply_to: EmailAddress | None
    return_path: str
    recipients: tuple[EmailAddress, ...]
    cc: tuple[EmailAddress, ...]
    bcc: tuple[EmailAddress, ...]
    subject: str
    date: str
    message_id: str
    mime_version: str
    content_type: str
    priority: str
    body: str
    html_body: str
    attachments: tuple[EmailAttachment, ...]
    urls: tuple[str, ...]
    authentication_results: str
    headers: tuple[tuple[str, str], ...]

    @classmethod
    def parse(cls, raw: str) -> EmailMessage:
        """Parse a raw RFC-822 email message.

        Args:
            raw: The raw email text (headers and body).

        Returns:
            The parsed :class:`EmailMessage`.

        Raises:
            ValidationError: If the input is empty or too large.
        """
        if not raw or not raw.strip():
            raise ValidationError("Email content must not be empty")
        if len(raw) > _MAX_RAW_LENGTH:
            raise ValidationError("Email content exceeds the maximum size")

        message: Message = message_from_string(raw)
        sender = EmailAddress.parse(message.get("From", ""))
        reply_to_raw = message.get("Reply-To")
        reply_to = EmailAddress.parse(reply_to_raw) if reply_to_raw else None
        recipients = tuple(
            EmailAddress(display_name=name.strip(), address=addr.strip().lower())
            for name, addr in getaddresses(message.get_all("To", []))
            if addr
        )
        cc = tuple(
            EmailAddress(display_name=name.strip(), address=addr.strip().lower())
            for name, addr in getaddresses(message.get_all("Cc", []))
            if addr
        )
        bcc = tuple(
            EmailAddress(display_name=name.strip(), address=addr.strip().lower())
            for name, addr in getaddresses(message.get_all("Bcc", []))
            if addr
        )
        body = cls._extract_body(message)
        html_body = cls._extract_body(message, content_type="text/html")
        attachments = cls._extract_attachments(message)
        urls = tuple(dict.fromkeys(_URL_PATTERN.findall(f"{body}\n{html_body}")))
        auth = " ".join(message.get_all("Authentication-Results", []))
        if not auth:
            auth = " ".join(message.get_all("Received-SPF", []))
        headers = tuple((key, str(value)) for key, value in message.items())

        return cls(
            raw=raw,
            sender=sender,
            reply_to=reply_to,
            return_path=(message.get("Return-Path", "") or "").strip(),
            recipients=recipients,
            cc=cc,
            bcc=bcc,
            subject=(message.get("Subject", "") or "").strip(),
            date=(message.get("Date", "") or "").strip(),
            message_id=(message.get("Message-ID", "") or "").strip(),
            mime_version=(message.get("MIME-Version", "") or "").strip(),
            content_type=(message.get_content_type() or "").strip(),
            priority=(message.get("X-Priority", "") or message.get("Importance", "") or "").strip(),
            body=body,
            html_body=html_body,
            attachments=attachments,
            urls=urls,
            authentication_results=auth.strip(),
            headers=headers,
        )

    @property
    def fingerprint(self) -> str:
        """A stable hash identifying the message (sender + subject + body)."""
        material = f"{self.sender.address}|{self.subject}|{self.body}"
        return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()

    @property
    def identity(self) -> str:
        """A human-readable identity for threat intelligence."""
        subject = self.subject or "(no subject)"
        return f"{self.sender.address} — {subject}"

    def authentication_breakdown(self) -> tuple[AuthMechanism, ...]:
        """Break the reported authentication results into SPF/DKIM/DMARC."""
        results = self.authentication_results.lower()
        present = bool(results)
        return tuple(
            self._auth_mechanism(name, results, present) for name in ("spf", "dkim", "dmarc")
        )

    @staticmethod
    def _auth_mechanism(name: str, results: str, present: bool) -> AuthMechanism:
        impact = _AUTH_IMPACT[name]
        if not present:
            return AuthMechanism(
                name=name.upper(),
                status=AuthStatus.NONE,
                reason="No authentication results were present in the message.",
                impact=impact,
            )
        if f"{name}=pass" in results:
            return AuthMechanism(
                name=name.upper(),
                status=AuthStatus.PASS,
                reason=f"{name.upper()} passed.",
                impact=impact,
            )
        if any(f"{name}={token}" in results for token in _AUTH_FAIL_TOKENS):
            return AuthMechanism(
                name=name.upper(),
                status=AuthStatus.FAIL,
                reason=f"{name.upper()} did not pass.",
                impact=impact,
            )
        if f"{name}=none" in results:
            return AuthMechanism(
                name=name.upper(),
                status=AuthStatus.WARNING,
                reason=f"{name.upper()} is not configured for this domain.",
                impact=impact,
            )
        return AuthMechanism(
            name=name.upper(),
            status=AuthStatus.WARNING,
            reason=f"{name.upper()} result was not reported.",
            impact=impact,
        )

    @staticmethod
    def _extract_body(message: Message, *, content_type: str = "text/plain") -> str:
        parts: list[str] = []
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == content_type and not part.get_filename():
                    parts.append(EmailMessage._decode(part))
        elif message.get_content_type() == content_type:
            parts.append(EmailMessage._decode(message))
        return "\n".join(p for p in parts if p)

    @staticmethod
    def _decode(part: Message) -> str:
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            content = part.get_payload()
            return content if isinstance(content, str) else ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, "replace")
        except (LookupError, ValueError):
            return payload.decode("utf-8", "replace")

    @staticmethod
    def _extract_attachments(message: Message) -> tuple[EmailAttachment, ...]:
        if not message.is_multipart():
            return ()
        attachments: list[EmailAttachment] = []
        for part in message.walk():
            filename = part.get_filename()
            if not filename:
                continue
            raw = part.get_payload(decode=True)
            payload = raw if isinstance(raw, bytes) else b""
            attachments.append(
                EmailAttachment(
                    filename=filename,
                    content_type=part.get_content_type(),
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        return tuple(attachments)

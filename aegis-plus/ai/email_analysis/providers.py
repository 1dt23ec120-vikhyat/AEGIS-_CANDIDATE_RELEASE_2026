"""Email evidence providers.

Offline, deterministic :class:`IEmailEvidenceProvider` implementations, each
contributing one independent source of evidence about a message: header
consistency, authentication results (SPF/DKIM/DMARC as reported in the message),
sender reputation and brand impersonation, social-engineering language, and
attachment metadata. Each returns an :class:`Evidence` with explainable
contributions; the hybrid analyzer combines them.

Live SPF/DKIM/DMARC validation (DNS + signature verification) is a future
network-backed enhancement; these providers read the authentication results
already present in the message, as an email gateway would.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.domain.analysis import FeatureContribution
from core.domain.email import (
    ARCHIVE_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
    MACRO_EXTENSIONS,
    EmailMessage,
)
from core.domain.intelligence import Evidence, EvidenceSource, ThreatCategory
from core.interfaces import IEmailEvidenceProvider

_ASCII_MAX = 127

_FREEMAIL_DOMAINS = frozenset(
    {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com", "proton.me"}
)
_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bank": "",
}
_URGENCY = (
    "urgent",
    "immediately",
    "action required",
    "within 24 hours",
    "account suspended",
    "suspended",
    "final notice",
    "verify your account",
    "confirm your identity",
)
_CREDENTIAL = (
    "verify your password",
    "update your payment",
    "confirm your password",
    "login to confirm",
    "click here to verify",
    "reset your password",
    "unusual sign-in",
    "validate your account",
)
_BEC = (
    "wire transfer",
    "gift card",
    "change bank details",
    "update banking",
    "are you available",
    "process this payment",
    "outstanding invoice",
    "purchase order",
)


@dataclass(frozen=True, slots=True)
class _Signal:
    feature: str
    detail: str
    weight: float
    triggered: bool


def _combine(
    signals: tuple[_Signal, ...],
    *,
    source: EvidenceSource,
    confidence: float,
    rationale: str,
    category: ThreatCategory,
    clean_category: ThreatCategory = ThreatCategory.NONE,
) -> Evidence:
    inverse = 1.0
    contributions: list[FeatureContribution] = []
    for signal in signals:
        contributions.append(
            FeatureContribution(
                feature=signal.feature,
                detail=signal.detail,
                weight=signal.weight,
                triggered=signal.triggered,
            )
        )
        if signal.triggered:
            inverse *= 1.0 - signal.weight
    risk = round(1.0 - inverse, 4)
    return Evidence(
        source=source,
        risk=risk,
        confidence=confidence,
        weight=1.0,
        rationale=rationale,
        category=category if risk > 0 else clean_category,
        contributions=tuple(contributions),
        available=True,
    )


class HeaderAnalysisProvider(IEmailEvidenceProvider):
    """Detects header inconsistencies (spoofing indicators)."""

    @property
    def source(self) -> EvidenceSource:
        """Header evidence source."""
        return EvidenceSource.HEADER

    def assess(self, email: EmailMessage) -> Evidence:
        """Return header-consistency evidence."""
        from_domain = email.sender.domain
        reply_mismatch = bool(
            email.reply_to and email.reply_to.is_present and email.reply_to.domain != from_domain
        )
        return_mismatch = bool(
            email.return_path and from_domain and from_domain not in email.return_path.lower()
        )
        signals = (
            _Signal(
                "reply_to_mismatch",
                "Reply-To domain differs from the From domain",
                0.45,
                reply_mismatch,
            ),
            _Signal(
                "return_path_mismatch",
                "Return-Path does not match the From address",
                0.30,
                return_mismatch,
            ),
            _Signal(
                "missing_sender",
                "Message has no valid From address",
                0.40,
                not email.sender.is_present,
            ),
        )
        return _combine(
            signals,
            source=self.source,
            confidence=0.7,
            rationale="Header consistency analysis",
            category=ThreatCategory.SUSPICIOUS_SENDER,
        )


class AuthenticationProvider(IEmailEvidenceProvider):
    """Reads SPF/DKIM/DMARC results reported in the message."""

    @property
    def source(self) -> EvidenceSource:
        """Authentication evidence source."""
        return EvidenceSource.AUTHENTICATION

    def assess(self, email: EmailMessage) -> Evidence:
        """Return email-authentication evidence."""
        results = email.authentication_results.lower()
        present = bool(results)
        spf_fail = any(f"spf={x}" in results for x in ("fail", "softfail", "none"))
        dkim_fail = any(f"dkim={x}" in results for x in ("fail", "none"))
        dmarc_fail = any(f"dmarc={x}" in results for x in ("fail", "none"))
        signals = (
            _Signal("spf_failed", "SPF did not pass", 0.45, spf_fail),
            _Signal("dkim_failed", "DKIM did not pass", 0.40, dkim_fail),
            _Signal("dmarc_failed", "DMARC did not pass", 0.50, dmarc_fail),
        )
        evidence = _combine(
            signals,
            source=self.source,
            confidence=0.85 if present else 0.4,
            rationale=(
                "Email authentication (SPF/DKIM/DMARC) results"
                if present
                else "No authentication results present in the message"
            ),
            # Authentication proves the message is spoofed, not what the attacker
            # is attempting. The threat's nature is categorized by the sender,
            # language, attachment, and URL providers, so this stays neutral and
            # contributes risk without claiming the primary category.
            category=ThreatCategory.NONE,
        )
        return evidence


class SenderReputationProvider(IEmailEvidenceProvider):
    """Detects sender spoofing and brand impersonation."""

    @property
    def source(self) -> EvidenceSource:
        """Sender evidence source."""
        return EvidenceSource.SENDER

    def assess(self, email: EmailMessage) -> Evidence:
        """Return sender-reputation evidence."""
        display = email.sender.display_name.lower()
        domain = email.sender.domain
        impersonated = ""
        for brand, brand_domain in _BRANDS.items():
            if brand in display and brand_domain and not domain.endswith(brand_domain):
                impersonated = brand
                break
        freemail_corporate = bool(
            domain in _FREEMAIL_DOMAINS
            and any(w in display for w in ("support", "team", "inc", "ltd", "service"))
        )
        signals = (
            _Signal(
                "brand_impersonation",
                f"Display name claims '{impersonated}' but domain is {domain or 'unknown'}",
                0.6,
                bool(impersonated),
            ),
            _Signal(
                "freemail_corporate_identity",
                "Corporate-sounding sender uses a free email domain",
                0.35,
                freemail_corporate,
            ),
            _Signal(
                "non_ascii_sender_domain",
                "Sender domain contains non-ASCII (homograph) characters",
                0.4,
                any(ord(ch) > _ASCII_MAX for ch in domain),
            ),
        )
        category = (
            ThreatCategory.BRAND_IMPERSONATION if impersonated else ThreatCategory.SUSPICIOUS_SENDER
        )
        return _combine(
            signals,
            source=self.source,
            confidence=0.75,
            rationale="Sender reputation and brand-impersonation analysis",
            category=category,
        )


class LanguageProvider(IEmailEvidenceProvider):
    """Detects social-engineering language."""

    @property
    def source(self) -> EvidenceSource:
        """Language evidence source."""
        return EvidenceSource.LANGUAGE

    def assess(self, email: EmailMessage) -> Evidence:
        """Return language-analysis evidence."""
        text = f"{email.subject}\n{email.body}".lower()
        urgency = any(phrase in text for phrase in _URGENCY)
        credential = any(phrase in text for phrase in _CREDENTIAL)
        bec = any(phrase in text for phrase in _BEC)
        signals = (
            _Signal("urgency_language", "Uses urgency or pressure language", 0.35, urgency),
            _Signal(
                "credential_request",
                "Requests credentials or account verification",
                0.5,
                credential,
            ),
            _Signal(
                "bec_language",
                "Contains business-email-compromise cues",
                0.5,
                bec,
            ),
        )
        if credential:
            category = ThreatCategory.CREDENTIAL_HARVESTING
        elif bec:
            category = ThreatCategory.BUSINESS_EMAIL_COMPROMISE
        else:
            category = ThreatCategory.PHISHING
        return _combine(
            signals,
            source=self.source,
            confidence=0.65,
            rationale="Social-engineering language analysis",
            category=category,
        )


class AttachmentProvider(IEmailEvidenceProvider):
    """Assesses attachment metadata for delivery risk."""

    @property
    def source(self) -> EvidenceSource:
        """Attachment evidence source."""
        return EvidenceSource.ATTACHMENT

    def assess(self, email: EmailMessage) -> Evidence:
        """Return attachment-metadata evidence."""
        exts = [a.extension for a in email.attachments]
        double_ext = any(a.has_double_extension for a in email.attachments)
        signals = (
            _Signal(
                "dangerous_attachment",
                "Attachment has an executable/dangerous extension",
                0.7,
                any(e in DANGEROUS_EXTENSIONS for e in exts),
            ),
            _Signal(
                "macro_attachment",
                "Attachment is a macro-enabled Office document",
                0.5,
                any(e in MACRO_EXTENSIONS for e in exts),
            ),
            _Signal(
                "archive_attachment",
                "Attachment is an archive that may hide a payload",
                0.3,
                any(e in ARCHIVE_EXTENSIONS for e in exts),
            ),
            _Signal(
                "double_extension",
                "Attachment uses a deceptive double extension",
                0.6,
                double_ext,
            ),
        )
        return _combine(
            signals,
            source=self.source,
            confidence=0.8,
            rationale="Attachment metadata analysis",
            category=ThreatCategory.MALWARE_DELIVERY,
        )

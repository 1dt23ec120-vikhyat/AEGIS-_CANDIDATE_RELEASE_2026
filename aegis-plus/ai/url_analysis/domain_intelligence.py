"""Structural domain intelligence.

An offline :class:`IDomainIntelligenceProvider` that assesses the domain of a URL
without any network calls: homograph / IDN / mixed-script spoofing, suspicious
TLDs, embedded credentials, and structural anomalies. This provides real,
deterministic domain intelligence and hardens the engine against Unicode-based
deception. Network-backed providers (WHOIS, DNS, certificate) are added as
separate adapters behind the same port.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.domain.analysis import FeatureContribution
from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    ThreatCategory,
)
from core.domain.url import Url
from core.interfaces import IDomainIntelligenceProvider

_ASCII_MAX = 127
_MAX_HOSTNAME_LEN = 40

_SUSPICIOUS_TLDS = frozenset(
    {
        "top",
        "xyz",
        "tk",
        "gq",
        "ml",
        "cf",
        "ga",
        "zip",
        "mov",
        "country",
        "kim",
        "work",
        "click",
        "link",
        "loan",
        "download",
        "review",
    }
)


@dataclass(frozen=True, slots=True)
class _Signal:
    feature: str
    detail: str
    weight: float
    triggered: bool


def _has_non_ascii(text: str) -> bool:
    return any(ord(ch) > _ASCII_MAX for ch in text)


def _has_mixed_script(host: str) -> bool:
    for label in host.split("."):
        has_ascii_letter = any(ch.isalpha() and ord(ch) <= _ASCII_MAX for ch in label)
        has_non_ascii_letter = any(ch.isalpha() and ord(ch) > _ASCII_MAX for ch in label)
        if has_ascii_letter and has_non_ascii_letter:
            return True
    return False


def _authority(raw: str) -> str:
    after_scheme = raw.split("://", 1)[-1]
    return after_scheme.split("/", 1)[0]


class StructuralDomainIntelligenceProvider(IDomainIntelligenceProvider):
    """Assesses domain structure and Unicode deception signals, offline."""

    def assess(self, url: Url) -> Evidence:
        """Return domain-intelligence evidence for ``url``."""
        host = url.host
        tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
        signals = (
            _Signal(
                "homograph_domain",
                "Host contains non-ASCII characters that can impersonate a brand",
                0.35,
                _has_non_ascii(host),
            ),
            _Signal(
                "mixed_script_domain",
                "Host mixes scripts within a label (spoofing indicator)",
                0.30,
                _has_mixed_script(host),
            ),
            _Signal(
                "punycode_domain",
                "Host uses punycode/IDN encoding",
                0.20,
                "xn--" in host.lower(),
            ),
            _Signal(
                "embedded_credentials",
                "URL embeds credentials in the authority",
                0.25,
                "@" in _authority(url.raw),
            ),
            _Signal(
                "suspicious_tld",
                f"Uses a frequently-abused TLD (.{tld})",
                0.15,
                tld in _SUSPICIOUS_TLDS,
            ),
            _Signal(
                "long_hostname",
                "Unusually long hostname",
                0.08,
                len(host) > _MAX_HOSTNAME_LEN,
            ),
        )

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
        deceptive = any(
            s.triggered
            for s in signals
            if s.feature in {"homograph_domain", "mixed_script_domain", "punycode_domain"}
        )
        if deceptive:
            category = ThreatCategory.DECEPTIVE_DOMAIN
        elif risk > 0:
            category = ThreatCategory.SUSPICIOUS_STRUCTURE
        else:
            category = ThreatCategory.NONE

        return Evidence(
            source=EvidenceSource.DOMAIN,
            risk=risk,
            confidence=0.75,
            weight=1.0,
            rationale="Offline domain-structure and Unicode-deception analysis",
            category=category,
            contributions=tuple(contributions),
            available=True,
        )

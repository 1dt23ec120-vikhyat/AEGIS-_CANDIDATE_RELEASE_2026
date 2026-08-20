"""Indicator-of-compromise (IOC) extraction.

The single IOC extraction engine for the whole platform.  It scans arbitrary text
and returns the network and host indicators it contains — URLs, domains, IPv4 and
IPv6 addresses, email addresses, common file hashes, JWT tokens, AWS keys, API
keys, Discord webhooks and Bitcoin wallets — normalized, de-duplicated and tagged
with stable identifiers suitable for future Threat Graph integration.

This lives in the domain and depends only on the standard library, so it can be
reused by URL analysis, email analysis, file analysis, reporting, and any future
module without pulling in a service dependency.  Extraction is a pure function of
its input: no I/O, no network, no state.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------------------

_DEFANG = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("[:]", ":"),
)


def refang(text: str) -> str:
    """Restore defanged indicators (``hxxp``, ``[.]``) to their real form."""
    result = text
    for token, replacement in _DEFANG:
        result = result.replace(token, replacement)
        result = result.replace(token.upper(), replacement)
    return result


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+" r"(?:[A-Za-z]{2,63})\b"
)
_HASH_RES = (
    ("sha256", re.compile(r"\b[A-Fa-f0-9]{64}\b")),
    ("sha1", re.compile(r"\b[A-Fa-f0-9]{40}\b")),
    ("md5", re.compile(r"\b[A-Fa-f0-9]{32}\b")),
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_API_KEY_RE = re.compile(
    r"(?:api[_-]?key|token|secret)[\"':\s=]+([A-Za-z0-9_\-]{20,})", re.IGNORECASE
)
_DISCORD_WEBHOOK_RE = re.compile(
    r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+", re.IGNORECASE
)
_BTC_LEGACY_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_BTC_BECH32_RE = re.compile(r"\bbc1[a-z0-9]{39,59}\b")

_MAX_INDICATORS = 500


# ---------------------------------------------------------------------------
# Stable identifier helpers (Threat Graph preparation)
# ---------------------------------------------------------------------------


def _ioc_id(indicator_type: str, value: str) -> str:
    """Deterministic, stable identifier for a single IOC value.

    Uses a UUID-5 namespace so the same indicator always maps to the same ID,
    enabling future Threat Graph edge construction without requiring the graph
    to exist yet.
    """
    namespace = uuid.UUID("a3f1c2d4-5e6f-7a8b-9c0d-e1f2a3b4c5d6")
    return str(uuid.uuid5(namespace, f"{indicator_type}:{value}"))


@dataclass(frozen=True, slots=True)
class TaggedIndicator:
    """An indicator with a stable ID, type tag, and the raw value."""

    ioc_id: str
    indicator_type: str
    value: str


# ---------------------------------------------------------------------------
# IocCollection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IocCollection:
    """A normalized, de-duplicated set of indicators extracted from text."""

    urls: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    ipv4_addresses: tuple[str, ...] = ()
    ipv6_addresses: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()
    jwt_tokens: tuple[str, ...] = ()
    aws_keys: tuple[str, ...] = ()
    api_keys: tuple[str, ...] = ()
    discord_webhooks: tuple[str, ...] = ()
    bitcoin_wallets: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        """The total number of distinct indicators across all types."""
        return (
            len(self.urls)
            + len(self.domains)
            + len(self.ipv4_addresses)
            + len(self.ipv6_addresses)
            + len(self.emails)
            + len(self.hashes)
            + len(self.jwt_tokens)
            + len(self.aws_keys)
            + len(self.api_keys)
            + len(self.discord_webhooks)
            + len(self.bitcoin_wallets)
        )

    @property
    def is_empty(self) -> bool:
        """Whether no indicators were found."""
        return self.total == 0

    def merged_with(self, other: IocCollection) -> IocCollection:
        """Return a new collection combining these indicators with ``other``."""
        return IocCollection(
            urls=_dedupe(self.urls + other.urls),
            domains=_dedupe(self.domains + other.domains),
            ipv4_addresses=_dedupe(self.ipv4_addresses + other.ipv4_addresses),
            ipv6_addresses=_dedupe(self.ipv6_addresses + other.ipv6_addresses),
            emails=_dedupe(self.emails + other.emails),
            hashes=_dedupe(self.hashes + other.hashes),
            jwt_tokens=_dedupe(self.jwt_tokens + other.jwt_tokens),
            aws_keys=_dedupe(self.aws_keys + other.aws_keys),
            api_keys=_dedupe(self.api_keys + other.api_keys),
            discord_webhooks=_dedupe(self.discord_webhooks + other.discord_webhooks),
            bitcoin_wallets=_dedupe(self.bitcoin_wallets + other.bitcoin_wallets),
        )

    def tagged(self) -> tuple[TaggedIndicator, ...]:
        """Return every indicator as a :class:`TaggedIndicator` with stable ID."""
        items: list[TaggedIndicator] = []
        for itype, values in (
            ("url", self.urls),
            ("domain", self.domains),
            ("ipv4", self.ipv4_addresses),
            ("ipv6", self.ipv6_addresses),
            ("email", self.emails),
            ("hash", self.hashes),
            ("jwt", self.jwt_tokens),
            ("aws_key", self.aws_keys),
            ("api_key", self.api_keys),
            ("discord_webhook", self.discord_webhooks),
            ("bitcoin_wallet", self.bitcoin_wallets),
        ):
            for value in values:
                items.append(TaggedIndicator(_ioc_id(itype, value), itype, value))
        return tuple(items)


# ---------------------------------------------------------------------------
# IOCStatistics
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IOCStatistics:
    """Aggregate counts by indicator type, ready for dashboards and reports."""

    url_count: int = 0
    domain_count: int = 0
    ipv4_count: int = 0
    ipv6_count: int = 0
    email_count: int = 0
    hash_count: int = 0
    jwt_count: int = 0
    aws_key_count: int = 0
    api_key_count: int = 0
    discord_webhook_count: int = 0
    bitcoin_wallet_count: int = 0
    total: int = 0


# ---------------------------------------------------------------------------
# IOCExtractionResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IOCExtractionResult:
    """The output of the platform IOC extraction engine.

    Wraps the collection with statistics and the source identifier, preparing
    for future confidence scoring, source attribution, and Threat Graph edges.
    """

    collection: IocCollection
    statistics: IOCStatistics
    source: str = ""
    artifact_id: str = ""


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract_iocs(text: str, *, source: str = "", artifact_id: str = "") -> IocCollection:
    """Extract all supported indicators from ``text``.

    Args:
        text: Arbitrary text to scan (email body, file strings, report, ...).
        source: Optional label identifying the extraction origin.
        artifact_id: Optional artifact identity for Threat Graph linkage.

    Returns:
        A normalized, de-duplicated :class:`IocCollection`.
    """
    if not text:
        return IocCollection()
    fanged = refang(text)

    urls = _dedupe(match.group(0).rstrip(".,);") for match in _URL_RE.finditer(fanged))
    ipv4 = _dedupe(match.group(0) for match in _IPV4_RE.finditer(fanged))
    ipv6 = _dedupe(match.group(0) for match in _IPV6_RE.finditer(fanged))
    emails = _dedupe(match.group(0).lower() for match in _EMAIL_RE.finditer(fanged))

    hashes: list[str] = []
    consumed: list[tuple[int, int]] = []
    for _, pattern in _HASH_RES:
        for match in pattern.finditer(fanged):
            span = match.span()
            if any(start <= span[0] < end for start, end in consumed):
                continue
            consumed.append(span)
            hashes.append(match.group(0).lower())

    covered = " ".join(urls) + " " + " ".join(emails)
    domains = _dedupe(
        match.group(0).lower()
        for match in _DOMAIN_RE.finditer(fanged)
        if match.group(0).lower() not in covered and not _IPV4_RE.fullmatch(match.group(0))
    )

    jwt_tokens = _dedupe(match.group(0) for match in _JWT_RE.finditer(fanged))
    aws_keys = _dedupe(match.group(0) for match in _AWS_KEY_RE.finditer(fanged))
    api_keys = _dedupe(match.group(1) for match in _API_KEY_RE.finditer(fanged))
    discord = _dedupe(match.group(0) for match in _DISCORD_WEBHOOK_RE.finditer(fanged))
    btc = _dedupe(
        match.group(0)
        for pattern in (_BTC_LEGACY_RE, _BTC_BECH32_RE)
        for match in pattern.finditer(fanged)
    )

    return IocCollection(
        urls=urls[:_MAX_INDICATORS],
        domains=domains[:_MAX_INDICATORS],
        ipv4_addresses=ipv4[:_MAX_INDICATORS],
        ipv6_addresses=ipv6[:_MAX_INDICATORS],
        emails=emails[:_MAX_INDICATORS],
        hashes=_dedupe(hashes)[:_MAX_INDICATORS],
        jwt_tokens=jwt_tokens[:_MAX_INDICATORS],
        aws_keys=aws_keys[:_MAX_INDICATORS],
        api_keys=api_keys[:_MAX_INDICATORS],
        discord_webhooks=discord[:_MAX_INDICATORS],
        bitcoin_wallets=btc[:_MAX_INDICATORS],
    )


def ioc_statistics(collection: IocCollection) -> IOCStatistics:
    """Compute aggregate statistics for a collection."""
    return IOCStatistics(
        url_count=len(collection.urls),
        domain_count=len(collection.domains),
        ipv4_count=len(collection.ipv4_addresses),
        ipv6_count=len(collection.ipv6_addresses),
        email_count=len(collection.emails),
        hash_count=len(collection.hashes),
        jwt_count=len(collection.jwt_tokens),
        aws_key_count=len(collection.aws_keys),
        api_key_count=len(collection.api_keys),
        discord_webhook_count=len(collection.discord_webhooks),
        bitcoin_wallet_count=len(collection.bitcoin_wallets),
        total=collection.total,
    )


def extract_iocs_full(text: str, *, source: str = "", artifact_id: str = "") -> IOCExtractionResult:
    """Extract IOCs and return a full extraction result with statistics."""
    collection = extract_iocs(text, source=source, artifact_id=artifact_id)
    return IOCExtractionResult(
        collection=collection,
        statistics=ioc_statistics(collection),
        source=source,
        artifact_id=artifact_id,
    )


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    """Return values as an order-preserving de-duplicated tuple."""
    seen: dict[str, None] = {}
    for value in values:
        if value and value not in seen:
            seen[value] = None
    return tuple(seen)

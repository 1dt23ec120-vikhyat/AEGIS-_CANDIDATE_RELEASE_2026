"""URL value object.

An immutable, validated URL. Parsing and validation use only the standard
library, keeping the domain framework-independent. Feature extraction and
analysis consume this value object rather than raw strings.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.domain.value_objects import ValueObject
from core.exceptions import ValidationError

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_MAX_URL_LENGTH = 2048


@dataclass(frozen=True, slots=True)
class Url(ValueObject):
    """A validated URL and its parsed components."""

    raw: str
    scheme: str
    host: str
    path: str
    query: str
    fragment: str

    @classmethod
    def create(cls, value: str) -> Url:
        """Validate and parse a URL string.

        A missing scheme is treated as ``http`` so bare hostnames are accepted;
        the absence of TLS then contributes to the analysis rather than being
        rejected outright.

        Args:
            value: The raw URL text.

        Returns:
            The parsed :class:`Url`.

        Raises:
            ValidationError: If the value is empty, too long, malformed, or uses
                an unsupported scheme.
        """
        candidate = value.strip()
        if not candidate:
            raise ValidationError("URL must not be empty")
        if any(ch.isspace() for ch in candidate):
            raise ValidationError("URL must not contain whitespace")
        if len(candidate) > _MAX_URL_LENGTH:
            raise ValidationError("URL exceeds the maximum supported length")

        normalized = candidate if "://" in candidate else f"http://{candidate}"
        parts = urlsplit(normalized)

        if parts.scheme not in _ALLOWED_SCHEMES:
            raise ValidationError(f"Unsupported URL scheme: {parts.scheme!r}")
        host = parts.hostname
        if not host:
            raise ValidationError("URL must include a host")

        return cls(
            raw=normalized,
            scheme=parts.scheme,
            host=host,
            path=parts.path,
            query=parts.query,
            fragment=parts.fragment,
        )

    @property
    def is_ip_host(self) -> bool:
        """Whether the host is a bare IP address."""
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    @property
    def uses_https(self) -> bool:
        """Whether the URL uses HTTPS."""
        return self.scheme == "https"

    @property
    def fingerprint(self) -> str:
        """A stable content hash of the normalized URL (SHA-256 hex)."""
        return hashlib.sha256(self.raw.encode("utf-8")).hexdigest()

    def __str__(self) -> str:
        """Return the normalized URL string."""
        return self.raw

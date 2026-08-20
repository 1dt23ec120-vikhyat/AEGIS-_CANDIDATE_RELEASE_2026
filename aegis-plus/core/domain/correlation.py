"""Correlation domain model.

Framework-independent value objects used to relate malicious artifacts to one
another. An :class:`ArtifactRef` identifies one observable (a sender, domain,
URL, attachment hash, and so on) by *kind* plus a normalized value, so new
artifact kinds - files, IP addresses, processes, registry keys, cloud resources -
can be correlated later without a schema or algorithm change.

:func:`correlate` is a pure policy: given the artifacts of a new observation and
those of an existing incident, it returns the signals they share. Persistence,
scoring thresholds, and orchestration live outside the domain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_SUBJECT_NOISE = re.compile(r"(?i)^(re|fwd|fw)\s*:\s*")
_NON_WORD = re.compile(r"[^a-z0-9\s]+")
_DIGITS = re.compile(r"\d+")
_WHITESPACE = re.compile(r"\s+")
_SUBJECT_PATTERN_WORDS = 6


class ArtifactKind(str, Enum):
    """The kind of observable an artifact reference identifies.

    Extending this enum is the only change required to correlate a new observable
    type; the matching policy is kind-agnostic.
    """

    SENDER = "sender"
    REPLY_TO = "reply_to"
    DOMAIN = "domain"
    SUBJECT_PATTERN = "subject_pattern"
    URL = "url"
    URL_HASH = "url_hash"
    ATTACHMENT_HASH = "attachment_hash"
    FILE_HASH = "file_hash"
    FILE_NAME = "file_name"
    THREAT_ENTRY = "threat_entry"
    CATEGORY = "category"


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """A single correlatable observable."""

    kind: ArtifactKind
    value: str

    @property
    def key(self) -> str:
        """A stable identity for set operations and persistence."""
        return f"{self.kind.value}:{self.value}"

    @property
    def label(self) -> str:
        """A human-readable description of the observable."""
        return f"{self.kind.value.replace('_', ' ').title()}: {self.value}"


@dataclass(frozen=True, slots=True)
class CorrelationLink:
    """The shared evidence between a new observation and an incident."""

    shared: tuple[ArtifactRef, ...]

    @property
    def strength(self) -> int:
        """How many distinct observables are shared."""
        return len(self.shared)

    @property
    def kinds(self) -> tuple[ArtifactKind, ...]:
        """The distinct artifact kinds contributing to this link."""
        return tuple(dict.fromkeys(ref.kind for ref in self.shared))

    @property
    def rationale(self) -> str:
        """A human-readable explanation of why the artifacts correlate."""
        if not self.shared:
            return "No shared indicators"
        return "Shared " + ", ".join(kind.value.replace("_", " ") for kind in self.kinds)


def subject_pattern(subject: str) -> str:
    """Normalize a subject line into a comparable campaign pattern.

    Strips reply/forward prefixes, punctuation and digits, then keeps the leading
    significant words so that templated lures ("Invoice 4821 overdue" and
    "Invoice 9142 overdue") collapse to the same pattern.
    """
    text = _SUBJECT_NOISE.sub("", subject or "").lower()
    text = _NON_WORD.sub(" ", text)
    text = _DIGITS.sub("", text)
    words = _WHITESPACE.sub(" ", text).strip().split()
    return " ".join(words[:_SUBJECT_PATTERN_WORDS])


def correlate(
    artifacts: tuple[ArtifactRef, ...], existing: tuple[ArtifactRef, ...]
) -> CorrelationLink:
    """Return the observables shared between two artifact sets.

    Args:
        artifacts: Artifacts of the new observation.
        existing: Artifacts already attributed to an incident.

    Returns:
        The :class:`CorrelationLink` describing the shared evidence.
    """
    known = {ref.key for ref in existing}
    shared = tuple(ref for ref in artifacts if ref.key in known)
    return CorrelationLink(shared=shared)

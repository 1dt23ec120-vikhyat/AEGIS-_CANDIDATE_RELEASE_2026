"""Email analyzer ports.

Contracts for the email intelligence engine, mirroring the URL analyzer design.
An :class:`IEmailEvidenceProvider` contributes one source of evidence about a
message; an :class:`IEmailAnalyzer` combines provider evidence (plus any evidence
supplied by the caller, such as embedded-URL results) into a report. Owned by
Core so services depend only on these abstractions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.email import EmailMessage
from core.domain.intelligence import Evidence, EvidenceSource, IntelligenceReport


class IEmailEvidenceProvider(ABC):
    """Contributes one source of evidence about an email message."""

    @property
    @abstractmethod
    def source(self) -> EvidenceSource:
        """The evidence source this provider represents."""

    @abstractmethod
    def assess(self, email: EmailMessage) -> Evidence:
        """Return evidence for ``email`` from this source."""


class IEmailAnalyzer(ABC):
    """Combines multi-source evidence about an email into a report."""

    @abstractmethod
    def analyze(
        self, email: EmailMessage, *, extra_evidence: tuple[Evidence, ...] = ()
    ) -> IntelligenceReport:
        """Analyze ``email`` and return a combined intelligence report.

        Args:
            email: The parsed message.
            extra_evidence: Additional evidence gathered by the caller (for
                example, embedded-URL analysis or prior threat intelligence).
        """

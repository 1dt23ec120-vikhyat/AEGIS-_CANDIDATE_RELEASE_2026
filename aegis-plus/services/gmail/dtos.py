"""Gmail workspace read-model DTOs (M14 completion).

Framework-free presentation records for the Gmail Intelligence analyst workspace.
They project the **existing** AEGIS+ intelligence for a Gmail-derived message —
the persisted :class:`~core.entities.email_scan.EmailScan`, its investigation,
and any incident/campaign correlation — into a shape the API/UI can render. They
compute no new intelligence: every risk/verdict/evidence value is taken verbatim
from the existing scan, and the safe preview is derived on demand from the raw
message purely for display.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.domain.gmail import GmailMessageStatus


@dataclass(frozen=True, slots=True)
class GmailEvidenceItem:
    """One triggered explainable contribution from the existing scan."""

    feature: str
    detail: str
    weight: float


@dataclass(frozen=True, slots=True)
class GmailSourceItem:
    """One intelligence source's contribution summary from the existing scan."""

    source: str
    risk_percent: int
    confidence: float
    available: bool
    rationale: str


@dataclass(frozen=True, slots=True)
class GmailUrlItem:
    """An embedded URL surfaced for the analyst — always treated as untrusted."""

    url: str
    verdict: str
    risk_percent: int
    blacklisted: bool


@dataclass(frozen=True, slots=True)
class GmailPreview:
    """A safe, non-executable preview of the message for the analyst.

    Rendered on demand from the raw message: plain-text body only, no remote
    content, no executable markup. URLs are listed (not linked) and attachments
    are shown as metadata only. ``error`` is set when the message could not be
    safely parsed for preview.
    """

    from_display: str
    from_address: str
    to: tuple[str, ...] = ()
    cc: tuple[str, ...] = ()
    subject: str = ""
    date: str = ""
    reply_to: str = ""
    plain_body: str = ""
    urls: tuple[GmailUrlItem, ...] = ()
    attachments: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True, slots=True)
class GmailMessageView:
    """A row in the analyst message list (list projection)."""

    message_id: str
    thread_id: str
    sender: str
    subject: str
    received_at: str
    snippet: str
    status: GmailMessageStatus
    verdict: str = ""
    risk_percent: int = 0
    confidence: float = 0.0
    scan_id: str = ""

    @property
    def risk_band(self) -> str:
        """A coarse risk band the workspace filters/colours on.

        Derived only from the *existing* verdict — never a fabricated score.
        """
        if self.status is not GmailMessageStatus.ANALYZED:
            return "unanalyzed"
        verdict = self.verdict.lower()
        if verdict == "phishing":
            return "high_risk"
        if verdict == "suspicious":
            return "suspicious"
        return "benign"


@dataclass(frozen=True, slots=True)
class GmailMessageDetail:
    """The full analyst detail for one Gmail message.

    Combines the list projection, the existing scan's evidence/sources/URLs, the
    incident/campaign association, the focus identifiers used to navigate into the
    existing Investigation / Graph Explorer / Copilot experiences, and the safe
    on-demand preview. ``analysis_error`` explains a non-analyzed status.
    """

    view: GmailMessageView
    category: str = ""
    evidence_strength: float = 0.0
    url_count: int = 0
    malicious_url_count: int = 0
    evidence: tuple[GmailEvidenceItem, ...] = ()
    sources: tuple[GmailSourceItem, ...] = ()
    urls: tuple[GmailUrlItem, ...] = ()
    iocs: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    artifact_id: str = ""
    preview: GmailPreview | None = None
    analysis_error: str = ""

    # scan_id/verdict/etc. are read through ``view`` to avoid duplication.
    _reserved: tuple[str, ...] = field(default_factory=tuple, repr=False)

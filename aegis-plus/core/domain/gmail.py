"""Gmail connector domain (M14).

Framework-free domain types for the read-only Gmail *input connector*. Gmail is a
source of messages that are fed into the existing Email Analysis pipeline; these
types carry only what the connector needs and never any analysis logic.

Security note: OAuth tokens are secrets. :class:`GmailCredentials` exists so the
auth-store and gateway can pass tokens internally; it is never serialized into an
API/UI DTO, never logged, and never persisted anywhere but the protected token
store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum


class GmailMessageStatus(str, Enum):
    """Outcome of attempting to ingest one Gmail message (analyst-facing).

    The taxonomy separates a clean analysis from the three ways ingestion can
    fail, so the analyst can tell an unsupported message apart from a transient
    Gmail hiccup without ever seeing a stack trace:

    - :attr:`ANALYZED` — the message flowed through the existing Email Analysis
      pipeline and produced a scan (terminal; recorded, deduplicated).
    - :attr:`UNSUPPORTED` — the raw message could not be parsed into an
      :class:`~core.domain.email.EmailMessage` (malformed/unsupported RFC-822).
      Terminal and recorded: retrying cannot help, so it is not re-attempted.
    - :attr:`TRANSIENT` — a temporary Gmail/API failure while fetching. **Not**
      recorded, so the next synchronization retries the message.
    - :attr:`FAILED` — an unexpected error during analysis. Terminal and recorded
      to avoid re-processing a poison message on every sync.
    """

    ANALYZED = "analyzed"
    UNSUPPORTED = "unsupported"
    TRANSIENT = "transient"
    FAILED = "failed"

    @property
    def is_recorded(self) -> bool:
        """Whether this outcome is persisted (terminal) vs. retried next sync."""
        return self is not GmailMessageStatus.TRANSIENT


@dataclass(frozen=True, slots=True)
class GmailCredentials:
    """OAuth 2.0 credentials for a connected Gmail account.

    ``access_token`` is short-lived; ``refresh_token`` is used to obtain new
    access tokens. Both are secrets and must never be logged or exposed.
    """

    access_token: str
    refresh_token: str
    token_type: str
    scope: str
    expires_at: datetime

    def is_expired(self, *, now: datetime | None = None, skew_seconds: int = 60) -> bool:
        """Whether the access token is expired (with a small safety skew).

        Robust to a naive ``expires_at`` (interpreted as UTC).
        """
        moment = now or datetime.now(UTC)
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return moment.timestamp() >= (expiry.timestamp() - skew_seconds)


@dataclass(frozen=True, slots=True)
class GmailAccount:
    """The connected Gmail account's public identity (safe to surface).

    Deliberately hash/token-free: only the address and connection metadata.
    """

    email_address: str
    connected_at: datetime
    scope: str

    @property
    def is_read_only(self) -> bool:
        """Whether the granted scope is the expected read-only Gmail scope."""
        return "gmail.readonly" in self.scope


@dataclass(frozen=True, slots=True)
class GmailMessageRef:
    """A lightweight reference to a Gmail message (from a list query).

    Carries just enough for the analyst to choose messages to ingest; the full
    raw message is fetched on demand.
    """

    message_id: str
    thread_id: str
    snippet: str = ""
    subject: str = ""
    sender: str = ""
    received_at: str = ""


@dataclass(frozen=True, slots=True)
class GmailProcessedMessage:
    """A persisted Gmail message record for the analyst workspace read-model.

    Carries only non-secret header metadata plus the resulting AEGIS+ ``scan_id``
    and the ingestion :class:`GmailMessageStatus`. It never holds the email body,
    full headers, attachments, or any OAuth material — the body is fetched on
    demand and rendered safely when the analyst opens a message.

    ``account_email`` scopes every record to the Gmail account that produced it,
    so messages from different demonstration accounts can never be mixed and
    deduplication is account-aware.
    """

    account_email: str
    message_id: str
    thread_id: str
    scan_id: str
    sender: str
    subject: str
    received_at: str
    snippet: str
    status: GmailMessageStatus
    processed_at: datetime


@dataclass(frozen=True, slots=True)
class GmailRawMessage:
    """A fetched Gmail message as raw RFC-822 text.

    ``raw`` is exactly what the existing ``EmailMessage.parse`` /
    ``EmailAnalysisService.analyze`` expect, so the connector reuses the entire
    email pipeline without duplicating any parsing or detection.
    """

    message_id: str
    raw: str

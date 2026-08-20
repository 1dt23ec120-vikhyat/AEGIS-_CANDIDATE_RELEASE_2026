"""Gmail synchronization-state port (M14).

Deduplication and read-model boundary for the Gmail connector. The Gmail message
id is the external identity, scoped by the connected ``account_email`` so that
messages from different demonstration accounts are isolated and deduplication is
account-aware. This port records which messages have been ingested — together
with the minimal, non-secret metadata the analyst workspace needs (sender,
subject, received time, snippet, status, and the resulting scan id) — so repeated
synchronization does not re-analyze the same message and the workspace can render
the message list without re-fetching from Gmail.

It stores no message body, no full headers, no attachments, and no OAuth secret.
It is deliberately minimal — a single-user desktop connector, not a distributed
queue.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.gmail import GmailProcessedMessage


class IGmailSyncStateRepository(ABC):
    """Tracks ingested Gmail messages and their workspace metadata."""

    @abstractmethod
    def is_processed(self, account_email: str, message_id: str) -> bool:
        """Whether a message id has already been ingested for an account."""

    @abstractmethod
    def get(self, account_email: str, message_id: str) -> GmailProcessedMessage | None:
        """Return the stored record for a message, or ``None`` if absent."""

    @abstractmethod
    def record(self, message: GmailProcessedMessage) -> None:
        """Persist (idempotently) the outcome of ingesting a message."""

    @abstractmethod
    def list_for_account(self, account_email: str) -> tuple[GmailProcessedMessage, ...]:
        """Return all stored records for an account, newest first."""

    @abstractmethod
    def processed_count(self, account_email: str) -> int:
        """Return the number of stored records for an account."""

    @abstractmethod
    def clear(self) -> None:
        """Remove all processed-message state (used on disconnect)."""

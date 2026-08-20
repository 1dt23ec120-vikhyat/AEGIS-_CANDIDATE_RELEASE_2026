"""Gmail synchronization-state repository (M14).

SQLAlchemy-backed implementation of :class:`IGmailSyncStateRepository`, bound to a
caller-supplied session. Records which Gmail messages have been ingested — scoped
by the connected account — together with the minimal, non-secret metadata the
analyst workspace renders. Stores no message body, no full headers, no
attachments, and no OAuth secret: only the external identity, header metadata, the
resulting scan id, and the ingestion status.
"""

from __future__ import annotations

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from core.domain.gmail import GmailMessageStatus, GmailProcessedMessage
from core.interfaces.gmail_sync_state import IGmailSyncStateRepository
from infrastructure.database.models import GmailProcessedMessageRow


class SqlAlchemyGmailSyncStateRepository(IGmailSyncStateRepository):
    """Deduplication + workspace read-model persistence for the Gmail connector."""

    def __init__(self, session: Session) -> None:
        """Initialize with an active session."""
        self._session = session

    def is_processed(self, account_email: str, message_id: str) -> bool:
        """Whether a message id has already been ingested for an account."""
        row = self._session.get(GmailProcessedMessageRow, (account_email, message_id))
        return row is not None

    def get(self, account_email: str, message_id: str) -> GmailProcessedMessage | None:
        """Return the stored record for a message, or ``None`` if absent."""
        row = self._session.get(GmailProcessedMessageRow, (account_email, message_id))
        return _to_domain(row) if row is not None else None

    def record(self, message: GmailProcessedMessage) -> None:
        """Persist (idempotently) the outcome of ingesting a message."""
        existing = self._session.get(
            GmailProcessedMessageRow, (message.account_email, message.message_id)
        )
        if existing is not None:
            existing.thread_id = message.thread_id
            existing.scan_id = message.scan_id
            existing.sender = message.sender
            existing.subject = message.subject
            existing.received_at = message.received_at
            existing.snippet = message.snippet
            existing.status = message.status.value
            existing.processed_at = message.processed_at
        else:
            self._session.add(
                GmailProcessedMessageRow(
                    account_email=message.account_email,
                    message_id=message.message_id,
                    thread_id=message.thread_id,
                    scan_id=message.scan_id,
                    sender=message.sender,
                    subject=message.subject,
                    received_at=message.received_at,
                    snippet=message.snippet,
                    status=message.status.value,
                    processed_at=message.processed_at,
                )
            )
        self._session.flush()

    def list_for_account(self, account_email: str) -> tuple[GmailProcessedMessage, ...]:
        """Return all stored records for an account, newest first."""
        rows = self._session.scalars(
            select(GmailProcessedMessageRow)
            .where(GmailProcessedMessageRow.account_email == account_email)
            .order_by(GmailProcessedMessageRow.processed_at.desc())
        ).all()
        return tuple(_to_domain(row) for row in rows)

    def processed_count(self, account_email: str) -> int:
        """Return the number of stored records for an account."""
        count = self._session.scalar(
            select(func.count())
            .select_from(GmailProcessedMessageRow)
            .where(GmailProcessedMessageRow.account_email == account_email)
        )
        return int(count or 0)

    def clear(self) -> None:
        """Remove all processed-message state (used on disconnect)."""
        self._session.execute(delete(GmailProcessedMessageRow))
        self._session.flush()


def _to_domain(row: GmailProcessedMessageRow) -> GmailProcessedMessage:
    return GmailProcessedMessage(
        account_email=row.account_email,
        message_id=row.message_id,
        thread_id=row.thread_id,
        scan_id=row.scan_id,
        sender=row.sender,
        subject=row.subject,
        received_at=row.received_at,
        snippet=row.snippet,
        status=GmailMessageStatus(row.status),
        processed_at=row.processed_at,
    )

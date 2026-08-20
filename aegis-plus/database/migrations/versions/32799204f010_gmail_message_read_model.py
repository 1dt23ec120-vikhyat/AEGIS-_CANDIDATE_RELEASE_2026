"""gmail message read-model (M14 completion)

Expands ``gmail_processed_messages`` from pure deduplication state into the
analyst-workspace read-model. Adds the connected ``account_email`` (making the
primary key composite and deduplication account-aware) plus the minimal,
non-secret header metadata the Gmail Intelligence workspace renders offline:
``thread_id``, ``sender``, ``subject``, ``received_at``, ``snippet`` and the
ingestion ``status``.

Additive to the schema as a whole and reversible. The table holds only
regenerable connector state (no message body, no full headers, no attachments,
no OAuth secret), so the upgrade recreates it with the richer shape rather than
attempting an in-place primary-key rewrite — clean and portable on SQLite.

Revision ID: 32799204f010
Revises: 2e323b64d4cd
Create Date: 2026-08-16 22:10:04.512094
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "32799204f010"
down_revision: str | None = "2e323b64d4cd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply the migration."""
    op.drop_table("gmail_processed_messages")
    op.create_table(
        "gmail_processed_messages",
        sa.Column("account_email", sa.String(length=320), nullable=False),
        sa.Column("message_id", sa.String(length=128), nullable=False),
        sa.Column("thread_id", sa.String(length=128), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("sender", sa.String(length=320), nullable=False),
        sa.Column("subject", sa.String(length=1024), nullable=False),
        sa.Column("received_at", sa.String(length=64), nullable=False),
        sa.Column("snippet", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "account_email", "message_id", name=op.f("pk_gmail_processed_messages")
        ),
    )
    with op.batch_alter_table("gmail_processed_messages", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_gmail_processed_messages_processed_at"), ["processed_at"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_gmail_processed_messages_status"), ["status"], unique=False
        )


def downgrade() -> None:
    """Revert the migration (restore the M14 deduplication-only shape)."""
    with op.batch_alter_table("gmail_processed_messages", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_gmail_processed_messages_status"))
        batch_op.drop_index(batch_op.f("ix_gmail_processed_messages_processed_at"))
    op.drop_table("gmail_processed_messages")
    op.create_table(
        "gmail_processed_messages",
        sa.Column("message_id", sa.String(length=128), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("message_id", name=op.f("pk_gmail_processed_messages")),
    )
    with op.batch_alter_table("gmail_processed_messages", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_gmail_processed_messages_processed_at"), ["processed_at"], unique=False
        )

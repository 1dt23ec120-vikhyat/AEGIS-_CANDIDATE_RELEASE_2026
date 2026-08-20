"""ORM row models.

Database-facing representations of domain entities. These use database-neutral
column types (``Uuid``, ``JSON``, timezone-aware ``DateTime``) so SQLite and
PostgreSQL remain interchangeable through configuration. Mapping between these
rows and Core entities lives in :mod:`infrastructure.database.mappers`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from infrastructure.database.base import Base


class AuditColumns:
    """Persistence audit columns shared by every row (DP-DB-08).

    Attribution (``created_by``/``updated_by``) is nullable until an
    authenticated actor context exists; ``version`` supports future optimistic
    concurrency control. These are persistence concerns and are deliberately
    absent from the Core domain entities.
    """

    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AuditLogRow(Base, AuditColumns):
    """Row model for the ``audit_logs`` table."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    action: Mapped[str] = mapped_column(String(255), index=True)
    outcome: Mapped[str] = mapped_column(String(32), index=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resource: Mapped[str | None] = mapped_column(String(255), nullable=True)
    context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ConfigurationRow(Base, AuditColumns):
    """Row model for the ``configurations`` table."""

    __tablename__ = "configurations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    key: Mapped[str] = mapped_column(String(255), unique=True)
    value: Mapped[str] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)


class UrlScanRow(Base, AuditColumns):
    """Row model for the ``url_scans`` table."""

    __tablename__ = "url_scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    url: Mapped[str] = mapped_column(String(2048))
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    threat_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    contributions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    category: Mapped[str] = mapped_column(String(32), default="none")
    evidence_strength: Mapped[float] = mapped_column(Float, default=0.0)
    sources: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ThreatEntryRow(Base, AuditColumns):
    """Row model for the ``threat_entries`` table (blacklist)."""

    __tablename__ = "threat_entries"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    artifact_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    artifact: Mapped[str] = mapped_column(String(2048))
    artifact_type: Mapped[str] = mapped_column(String(16), default="url", index=True)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    indicators: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    first_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    detection_count: Mapped[int] = mapped_column(Integer, default=1)
    blocked: Mapped[bool] = mapped_column(Boolean, default=True)
    block_source: Mapped[str] = mapped_column(String(32))
    notes: Mapped[str | None] = mapped_column(String(1024), nullable=True)


class EmailScanRow(Base, AuditColumns):
    """Row model for the ``email_scans`` table."""

    __tablename__ = "email_scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sender: Mapped[str] = mapped_column(String(320), index=True)
    subject: Mapped[str] = mapped_column(String(1024))
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    threat_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    category: Mapped[str] = mapped_column(String(32), default="none")
    evidence_strength: Mapped[float] = mapped_column(Float, default=0.0)
    contributions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    sources: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    url_count: Mapped[int] = mapped_column(Integer, default=0)
    malicious_url_count: Mapped[int] = mapped_column(Integer, default=0)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)


class EmailInvestigationRow(Base, AuditColumns):
    """Row model for the ``email_investigations`` table."""

    __tablename__ = "email_investigations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")


class FileScanRow(Base, AuditColumns):
    """Row model for the ``file_scans`` table.

    Stores only fingerprints, metadata and derived findings - never the uploaded
    bytes. Fingerprints are held as an ``algorithm -> value`` JSON map so that new
    fingerprint providers (SSDEEP, TLSH, ...) extend the record without a schema
    change; SHA-256 is duplicated into an indexed column for fast identity lookup.
    """

    __tablename__ = "file_scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    filename: Mapped[str] = mapped_column(String(255), index=True)
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    fingerprints: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    file_kind: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    detected_mime: Mapped[str] = mapped_column(String(128), default="")
    entropy: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    threat_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    category: Mapped[str] = mapped_column(String(32), default="none")
    evidence_strength: Mapped[float] = mapped_column(Float, default=0.0)
    contributions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    sources: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    indicator_count: Mapped[int] = mapped_column(Integer, default=0)
    url_count: Mapped[int] = mapped_column(Integer, default=0)
    malicious_url_count: Mapped[int] = mapped_column(Integer, default=0)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)


class FileInvestigationRow(Base, AuditColumns):
    """Row model for the ``file_investigations`` table."""

    __tablename__ = "file_investigations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    scan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")


class CampaignRow(Base, AuditColumns):
    """Row model for the ``campaigns`` table."""

    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    name: Mapped[str] = mapped_column(String(512), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    artifacts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    affected_users: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentRow(Base, AuditColumns):
    """Row model for the ``incidents`` table."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    title: Mapped[str] = mapped_column(String(512))
    category: Mapped[str] = mapped_column(String(32), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    artifacts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    scan_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    campaign_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    assignee: Mapped[str] = mapped_column(String(255), default="")
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    comments: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    events: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    affected_users: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UserAccountRow(Base):
    """Row model for the ``user_accounts`` table (M13).

    The single local AEGIS+ account. Only the password *hash* is stored; the
    plaintext password never reaches persistence. ``username`` and ``email`` are
    unique. A partial single-account constraint is enforced in the application
    service, not the schema, to keep the migration portable.
    """

    __tablename__ = "user_accounts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    full_name: Mapped[str] = mapped_column(String(120))
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))


class AuthSessionRow(Base):
    """Row model for the ``auth_sessions`` table (M13).

    An authenticated session bound to the local account. ``token`` is an opaque
    high-entropy secret and the primary key; ``expires_at`` bounds its validity.
    """

    __tablename__ = "auth_sessions"

    token: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class GmailProcessedMessageRow(Base):
    """Row model for the ``gmail_processed_messages`` table (M14).

    Deduplication and analyst-workspace read-model state for the read-only Gmail
    connector: one row per Gmail message that has been *attempted* against the
    Email Analysis pipeline. The composite primary key ``(account_email,
    message_id)`` scopes every row to the connected account, so messages from
    different demonstration accounts are isolated and deduplication is
    account-aware.

    Holds only non-secret header metadata (sender, subject, received time,
    snippet), the resulting ``scan_id``, and the ingestion ``status`` — never the
    email body, full headers, attachments, or any OAuth secret. The body is
    fetched on demand and rendered safely when the analyst opens a message.
    """

    __tablename__ = "gmail_processed_messages"

    account_email: Mapped[str] = mapped_column(String(320), primary_key=True)
    message_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    thread_id: Mapped[str] = mapped_column(String(128), default="")
    scan_id: Mapped[str] = mapped_column(String(64), default="")
    sender: Mapped[str] = mapped_column(String(320), default="")
    subject: Mapped[str] = mapped_column(String(1024), default="")
    received_at: Mapped[str] = mapped_column(String(64), default="")
    snippet: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(32), default="analyzed", index=True)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

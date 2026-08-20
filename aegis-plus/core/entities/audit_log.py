"""Audit log entity.

Represents a security-relevant audited action as a domain entity. Pure domain
model with no persistence concerns; the infrastructure layer maps it to and from
its database representation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.constants import AuditOutcome
from core.domain.value_objects import EntityId
from core.entities.base import BaseEntity


class AuditLog(BaseEntity):
    """A recorded, security-relevant action and its outcome."""

    def __init__(
        self,
        *,
        action: str,
        outcome: AuditOutcome,
        actor: str | None = None,
        resource: str | None = None,
        context: dict[str, Any] | None = None,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize an audit log entry.

        Args:
            action: The audited action (e.g. ``"application.start"``).
            outcome: The outcome classification.
            actor: Identifier of the responsible actor, if known.
            resource: Identifier of the affected resource, if applicable.
            context: Redacted structured context. Never contains secrets.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp (the audit time).
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        self.action = action
        self.outcome = outcome
        self.actor = actor
        self.resource = resource
        self.context: dict[str, Any] = context or {}

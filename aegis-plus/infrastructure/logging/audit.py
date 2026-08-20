"""Security audit logging with optional persistence.

Provides an injectable :class:`AuditLogger` that emits structured, security-
relevant audit records and, when configured, persists them through the Unit of
Work. Persistence is introduced transparently via dependency injection: call
sites remain unchanged whether or not a Unit of Work factory is supplied.

Audit persistence is best-effort and resilient - a persistence failure is logged
but never propagated, so auditing can never break the audited operation. Each
audit record is persisted in its own Unit of Work so it survives independently
of any surrounding business transaction.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from core.constants import AuditOutcome
from core.entities import AuditLog
from core.interfaces import IAuditTrail, ILogger, IUnitOfWork
from infrastructure.logging.redaction import redact_mapping


class AuditLogger(IAuditTrail):
    """Emits structured audit records and optionally persists them."""

    def __init__(
        self,
        logger: ILogger,
        *,
        unit_of_work_factory: Callable[[], IUnitOfWork] | None = None,
    ) -> None:
        """Initialize the audit logger.

        Args:
            logger: The injected centralized logger to emit through.
            unit_of_work_factory: Optional factory producing a Unit of Work used
                to persist audit records. When omitted, records are logged only.
        """
        self._logger = logger
        self._unit_of_work_factory = unit_of_work_factory

    def record(
        self,
        action: str,
        *,
        outcome: AuditOutcome,
        actor: str | None = None,
        resource: str | None = None,
        **context: Any,
    ) -> None:
        """Emit and (if configured) persist a structured audit record.

        Sensitive values in ``context`` are redacted both in the log and in the
        persisted record.

        Args:
            action: The action being audited (e.g. ``"application.start"``).
            outcome: The outcome classification.
            actor: Identifier of the actor responsible, if known.
            resource: Identifier of the affected resource, if applicable.
            **context: Additional structured context for the record.
        """
        bound = self._logger.bind(
            audit=True,
            action=action,
            outcome=outcome.value,
            actor=actor,
            resource=resource,
            **context,
        )
        message = f"audit: {action} -> {outcome.value}"

        if outcome is AuditOutcome.SUCCESS:
            bound.info(message)
        elif outcome is AuditOutcome.DENIED:
            bound.warning(message)
        else:
            bound.error(message)

        self._persist(action, outcome, actor, resource, context)

    def _persist(
        self,
        action: str,
        outcome: AuditOutcome,
        actor: str | None,
        resource: str | None,
        context: dict[str, Any],
    ) -> None:
        """Persist the audit record, tolerating failures."""
        if self._unit_of_work_factory is None:
            return
        try:
            entry = AuditLog(
                action=action,
                outcome=outcome,
                actor=actor,
                resource=resource,
                context=redact_mapping(context),
            )
            with self._unit_of_work_factory() as uow:
                uow.get_repository(AuditLog).add(entry)
                uow.commit()
        except Exception as exc:
            self._logger.warning("Audit persistence failed for {}: {}", action, exc)

    def success(self, action: str, **context: Any) -> None:
        """Record a successful action."""
        self.record(action, outcome=AuditOutcome.SUCCESS, **context)

    def failure(self, action: str, **context: Any) -> None:
        """Record a failed action."""
        self.record(action, outcome=AuditOutcome.FAILURE, **context)

    def denied(self, action: str, **context: Any) -> None:
        """Record a denied action."""
        self.record(action, outcome=AuditOutcome.DENIED, **context)

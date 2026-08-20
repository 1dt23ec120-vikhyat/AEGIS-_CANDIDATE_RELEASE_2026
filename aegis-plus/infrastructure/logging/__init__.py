"""Centralized logging and audit subsystem.

This package is the single sanctioned logging mechanism for AEGIS+. Application
code must obtain loggers via :func:`get_logger` and must not use the standard
library :mod:`logging` module or create ad-hoc loggers.

Configuration is explicit and performed once at the composition root via
:func:`configure_logging`; there are no import-time side effects. Components
receive the Core :class:`~core.interfaces.ILogger` contract (and, where needed,
an :class:`AuditLogger`) through dependency injection. This package provides the
implementation of that Core contract, not the contract itself.
"""

from core.constants import AuditOutcome
from infrastructure.logging.audit import AuditLogger
from infrastructure.logging.configuration import (
    configure_logging,
    is_configured,
    reset_logging,
)
from infrastructure.logging.logger import get_logger
from infrastructure.logging.redaction import REDACTED, redact_mapping

__all__ = [
    "REDACTED",
    "AuditLogger",
    "AuditOutcome",
    "configure_logging",
    "get_logger",
    "is_configured",
    "redact_mapping",
    "reset_logging",
]

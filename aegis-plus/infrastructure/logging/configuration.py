"""Centralized logging configuration.

Configures Loguru once, explicitly, at the composition root - there are no
import-time side effects. Three sinks are installed:

* **Console** - human-readable, colorized in development.
* **Application file** - rotating log of all records.
* **Audit file** - structured (JSON) log of security-relevant audit records
  only, selected by the ``audit`` context flag.

Secret safety is enforced by the redaction patcher and by disabling Loguru's
``diagnose`` outside development (so tracebacks cannot expose variable values).
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from loguru import logger

from config import Environment, ProjectPaths
from config.schemas import LoggingSettings
from infrastructure.logging.interception import install_stdlib_interception
from infrastructure.logging.redaction import patch_record

if TYPE_CHECKING:
    from loguru import Record

_CONSOLE_FORMAT: str = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{extra[name]}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

_FILE_FORMAT: str = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | " "{extra[name]}:{function}:{line} - {message}"
)

_APP_LOG_FILE: str = "aegis.log"
_AUDIT_LOG_FILE: str = "audit.log"


class _LoggingState:
    """Holds the configuration state of the logging subsystem."""

    configured: bool = False


_state = _LoggingState()


def _audit_only(record: Record) -> bool:
    """Sink filter selecting only audit records."""
    return bool(record["extra"].get("audit"))


def configure_logging(
    logging_settings: LoggingSettings,
    paths: ProjectPaths,
    *,
    environment: Environment,
    enqueue: bool = True,
    intercept_stdlib: bool = True,
) -> None:
    """Configure the centralized logging subsystem.

    Safe to call once at startup. Calling again reconfigures cleanly (existing
    sinks are removed first).

    Args:
        logging_settings: Logging policy (level, directory, rotation, retention).
        paths: Resolved project paths, used to locate the log directory.
        environment: Active runtime environment; controls colorization and
            whether diagnostic tracebacks are enabled.
        enqueue: Whether sinks write asynchronously via a queue (recommended in
            production for thread/process safety; disabled in tests for
            deterministic output).
        intercept_stdlib: Whether to route standard-library logging through
            Loguru so third-party output is centralized.
    """
    log_dir = paths.resolve(logging_settings.directory)
    log_dir.mkdir(parents=True, exist_ok=True)

    retention = f"{logging_settings.retention_days} days"
    diagnose = environment.is_development

    logger.remove()
    logger.configure(patcher=patch_record)

    logger.add(
        sys.stderr,
        level=logging_settings.level,
        format=_CONSOLE_FORMAT,
        colorize=environment.is_development,
        backtrace=True,
        diagnose=diagnose,
        enqueue=enqueue,
    )

    logger.add(
        log_dir / _APP_LOG_FILE,
        level=logging_settings.level,
        format=_FILE_FORMAT,
        rotation=logging_settings.rotation,
        retention=retention,
        encoding="utf-8",
        backtrace=True,
        diagnose=diagnose,
        enqueue=enqueue,
    )

    logger.add(
        log_dir / _AUDIT_LOG_FILE,
        level="INFO",
        filter=_audit_only,
        serialize=True,
        rotation=logging_settings.rotation,
        retention=retention,
        encoding="utf-8",
        enqueue=enqueue,
    )

    if intercept_stdlib:
        install_stdlib_interception()

    _state.configured = True


def is_configured() -> bool:
    """Return whether logging has been configured in this process."""
    return _state.configured


def reset_logging() -> None:
    """Remove all sinks and mark logging unconfigured.

    Primarily for tests and controlled reconfiguration. Removing sinks also
    flushes any queued records.
    """
    logger.remove()
    _state.configured = False

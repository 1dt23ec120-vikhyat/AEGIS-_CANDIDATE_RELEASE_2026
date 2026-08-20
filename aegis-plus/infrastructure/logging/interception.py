"""Standard-library logging interception.

Third-party libraries (uvicorn, SQLAlchemy, and others) emit through Python's
built-in :mod:`logging`. To honour the project logging standard - that all logs
flow through the centralized subsystem - this module bridges standard-library
records into Loguru.

The use of :mod:`logging` here is strictly a *bridge* for third-party output;
application code must never log through the standard library directly.
"""

from __future__ import annotations

import logging
from types import FrameType

from loguru import logger


class InterceptHandler(logging.Handler):
    """Routes standard-library log records into Loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        """Forward a standard-library record to the Loguru logger.

        Args:
            record: The standard-library log record to forward.
        """
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Walk back to the frame that originated the log call so file/line
        # information points at the real caller rather than the logging module.
        frame: FrameType | None = logging.currentframe()
        depth = 2
        while frame is not None and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def install_stdlib_interception() -> None:
    """Redirect standard-library logging through Loguru.

    Replaces the root logger's handlers with a single :class:`InterceptHandler`
    and neutralizes propagation on commonly noisy third-party loggers so their
    output is not duplicated.
    """
    logging.root.handlers = [InterceptHandler()]
    logging.root.setLevel(logging.NOTSET)

    for name in ("uvicorn", "uvicorn.access", "uvicorn.error", "sqlalchemy.engine"):
        third_party = logging.getLogger(name)
        third_party.handlers = []
        third_party.propagate = True

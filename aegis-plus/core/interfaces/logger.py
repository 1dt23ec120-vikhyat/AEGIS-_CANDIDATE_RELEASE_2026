"""Logging port.

``ILogger`` is the Core-owned logging contract. Infrastructure provides the
implementation (the centralized Loguru-based logger); components depend on this
protocol so the domain never references a logging framework.

Defined as a runtime-checkable :class:`~typing.Protocol` so structurally
compatible loggers (such as a bound Loguru logger) satisfy it without an
explicit adapter.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ILogger(Protocol):
    """Structural logging contract used across AEGIS+."""

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a message at DEBUG level."""
        ...

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a message at INFO level."""
        ...

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a message at WARNING level."""
        ...

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a message at ERROR level."""
        ...

    def critical(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a message at CRITICAL level."""
        ...

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a message at ERROR level with the active exception traceback."""
        ...

    def bind(self, **kwargs: Any) -> ILogger:
        """Return a logger bound with additional structured context."""
        ...

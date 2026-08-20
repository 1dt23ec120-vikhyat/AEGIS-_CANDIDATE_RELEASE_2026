"""Logger factory.

Provides named loggers for injection at the composition root. Every logger is
bound with a ``name`` identifying the component, which the log format renders.
Callers depend on the Core :class:`~core.interfaces.ILogger` contract rather
than on Loguru directly.
"""

from __future__ import annotations

from typing import cast

from loguru import logger

from core.interfaces import ILogger


def get_logger(name: str) -> ILogger:
    """Return a logger bound to ``name``.

    Args:
        name: Component identifier included in every emitted record (for
            example, a module or service name).

    Returns:
        A logger satisfying the Core :class:`ILogger` contract.
    """
    return cast(ILogger, logger.bind(name=name))

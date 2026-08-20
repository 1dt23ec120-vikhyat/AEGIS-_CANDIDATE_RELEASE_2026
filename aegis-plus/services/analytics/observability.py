"""Shared observability for analytics services.

A small base class and decorator that record per-operation execution counts and
durations, so every analytics/intelligence service exposes a uniform ``metrics()``
surface without duplicating the timing logic.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

_F = TypeVar("_F", bound=Callable[..., Any])


def tracked(method: _F) -> _F:
    """Record the wall-clock duration and count of a service operation."""

    @wraps(method)
    def wrapper(self: MeteredService, *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        try:
            return method(self, *args, **kwargs)
        finally:
            self._record(method.__name__, (time.perf_counter() - start) * 1000)

    return cast(_F, wrapper)


class MeteredService:
    """Base class providing uniform execution metrics."""

    def __init__(self) -> None:
        """Initialise the metric counters."""
        self._runs = 0
        self._total_ms = 0.0
        self._by_op: dict[str, int] = {}

    def _record(self, op: str, ms: float) -> None:
        self._runs += 1
        self._total_ms += ms
        self._by_op[op] = self._by_op.get(op, 0) + 1

    def metrics(self) -> dict[str, float]:
        """Execution observability: run count, durations, per-operation counts."""
        avg = self._total_ms / self._runs if self._runs else 0.0
        metrics: dict[str, float] = {
            "runs": float(self._runs),
            "total_ms": round(self._total_ms, 3),
            "avg_ms": round(avg, 3),
        }
        for op, count in self._by_op.items():
            metrics[f"op.{op}"] = float(count)
        return metrics

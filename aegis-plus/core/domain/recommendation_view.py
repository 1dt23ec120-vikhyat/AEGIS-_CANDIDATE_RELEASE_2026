"""Analyst recommendation contracts (view DTOs) for M11 Phase D.

Immutable, framework-free value objects produced by the deterministic
:class:`services.analytics.recommendations.RecommendationService`. Every
recommendation names a subject, a priority in ``[0, 1]``, and a ``rationale``
explaining *why* it was produced.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Recommendation:
    """A single deterministic, explainable analyst recommendation."""

    kind: str
    title: str
    subject_id: str = ""
    subject_type: str = ""
    priority: float = 0.0
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RecommendationSet:
    """An ordered set of recommendations for the SOC dashboard."""

    recommendations: tuple[Recommendation, ...] = ()

    @property
    def count(self) -> int:
        """Number of recommendations."""
        return len(self.recommendations)

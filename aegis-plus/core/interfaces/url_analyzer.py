"""URL analyzer port.

The contract an analyzer implements to score a URL. Owned by Core so the domain
and services depend only on the abstraction, never on a concrete model
(Dependency Inversion). Each analyzer identifies its evidence source, so the
hybrid engine can attribute and weight its contribution; a trained model and a
heuristic baseline coexist behind this one port.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.analysis import UrlAnalysis
from core.domain.intelligence import EvidenceSource
from core.domain.url import Url


class IUrlAnalyzer(ABC):
    """Analyzes a URL and returns an explainable result."""

    @property
    @abstractmethod
    def source(self) -> EvidenceSource:
        """The evidence source this analyzer represents (ML or heuristic)."""

    @abstractmethod
    def analyze(self, url: Url) -> UrlAnalysis:
        """Analyze ``url`` and return its :class:`UrlAnalysis`."""

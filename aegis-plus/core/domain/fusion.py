"""Intelligence fusion domain model.

Value objects for the cross-cutting concerns that unify the URL, email, and file
intelligence engines into a single fusion layer:

- :class:`Severity` — maps a risk score to a named level.
- :class:`ProviderInfo` — metadata describing one registered evidence provider.
- :class:`ProviderSummary` — a provider's contribution to a single analysis.
- :class:`IntelligenceRelationship` — a prepared-but-not-stored edge for the
  future Threat Graph, linking two artifacts by stable identifiers.
- :class:`FusionResult` — the enriched output of the evidence fusion service,
  wrapping the existing :class:`IntelligenceReport` with severity, analysis
  duration, recommendations, MITRE techniques, IOC summary, and provider
  summaries.

All value objects are frozen dataclasses with no I/O, no state, and no
framework dependency — they live in the domain and are consumed by services,
the API, and the UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from core.domain.intelligence import IntelligenceReport
from core.domain.ioc import IocCollection, IOCStatistics

_CRITICAL_THRESHOLD = 0.80
_HIGH_THRESHOLD = 0.60
_MEDIUM_THRESHOLD = 0.35


class Severity(str, Enum):
    """Named severity level derived from a risk score."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def severity_from_score(risk_score: float) -> Severity:
    """Map a ``[0, 1]`` risk score to a :class:`Severity`."""
    if risk_score >= _CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if risk_score >= _HIGH_THRESHOLD:
        return Severity.HIGH
    if risk_score >= _MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    if risk_score > 0:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    """Metadata describing one registered evidence provider.

    Supports future providers (YARA, VirusTotal, Sandbox, Sigma, Cloud
    Intelligence) without contract change — they add themselves to the
    registry with the same shape.
    """

    name: str
    version: str
    enabled: bool = True
    supported_artifact_types: tuple[str, ...] = ()
    supported_indicator_types: tuple[str, ...] = ()
    configuration: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProviderSummary:
    """A provider's contribution to a single analysis run."""

    name: str
    version: str
    execution_ms: float
    evidence_count: int
    risk: float
    confidence: float
    technique_ids: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Threat Graph relationship preparation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IntelligenceRelationship:
    """A directed edge between two artifacts, prepared for the Threat Graph.

    Neither the graph database nor storage is implemented yet; this VO carries
    the stable identifiers and relationship type so that services can accumulate
    relationships during analysis and a future graph module can persist them
    without changing the upstream code.
    """

    source_id: str
    source_type: str
    target_id: str
    target_type: str
    relationship: str
    confidence: float = 1.0

    @property
    def key(self) -> str:
        """A deduplication key for this relationship."""
        return (
            f"{self.source_type}:{self.source_id}"
            f"->{self.relationship}"
            f"->{self.target_type}:{self.target_id}"
        )


# ---------------------------------------------------------------------------
# Fusion result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FusionResult:
    """The enriched output of the intelligence fusion service.

    Wraps the existing :class:`IntelligenceReport` with cross-cutting fusion
    metadata that every intelligence engine contributes to.
    """

    report: IntelligenceReport
    severity: Severity
    analysis_duration_ms: float
    recommendations: tuple[str, ...]
    technique_ids: tuple[str, ...]
    ioc_summary: IOCStatistics
    provider_summaries: tuple[ProviderSummary, ...]
    relationships: tuple[IntelligenceRelationship, ...] = ()
    ioc_collection: IocCollection = field(default_factory=IocCollection)

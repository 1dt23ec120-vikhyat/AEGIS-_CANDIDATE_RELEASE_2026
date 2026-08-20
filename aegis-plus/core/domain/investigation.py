"""Unified Investigation domain model.

Artifact-agnostic value objects that every investigation workspace consumes.
The model supports URL, email, file, and all future artifact types (memory,
registry, PCAP, cloud, identity, container, mobile) without redesign — the
workspace reads these VOs and the artifact type determines which metadata
fields are populated, not which code path runs.

All VOs are frozen dataclasses with no I/O, no state, and no framework
dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EventKind(str, Enum):
    """The kind of event in an investigation timeline."""

    ANALYSIS_STARTED = "analysis_started"
    PROVIDER_EXECUTED = "provider_executed"
    EVIDENCE_DISCOVERED = "evidence_discovered"
    IOC_EXTRACTED = "ioc_extracted"
    THREAT_MATCH = "threat_match"
    CORRELATION = "correlation"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYST_COMMENT = "analyst_comment"


@dataclass(frozen=True, slots=True)
class InvestigationEvent:
    """One chronological event in an investigation timeline."""

    timestamp: str
    kind: EventKind
    source: str
    description: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceNode:
    """One node in a hierarchical evidence tree.

    The tree is: Artifact → Provider → Evidence → Contribution → Recommendation
    → MITRE Technique.  Children are rendered recursively by the UI.
    """

    label: str
    detail: str = ""
    risk: float = 0.0
    confidence: float = 0.0
    technique_id: str = ""
    recommendation: str = ""
    tone: str = "neutral"
    children: tuple[EvidenceNode, ...] = ()


@dataclass(frozen=True, slots=True)
class MetadataField:
    """A single metadata key-value pair for the adaptive metadata panel."""

    label: str
    value: str
    category: str = "general"


@dataclass(frozen=True, slots=True)
class InvestigationSummary:
    """The unified investigation model consumed by every workspace.

    Every field has a safe default so the workspace renders gracefully for any
    artifact type — a URL investigation simply leaves file-specific fields
    empty, and the workspace adapts.
    """

    investigation_id: str = ""
    artifact_id: str = ""
    artifact_type: str = ""
    status: str = "open"
    created_at: str = ""
    updated_at: str = ""
    analysis_duration_ms: float = 0.0
    verdict: str = ""
    severity: str = "info"
    confidence: float = 0.0
    confidence_source: str = ""
    category: str = "none"
    risk_percent: int = 0
    evidence_strength: float = 0.0
    malicious: bool = False
    timeline: tuple[InvestigationEvent, ...] = ()
    evidence_tree: tuple[EvidenceNode, ...] = ()
    metadata: tuple[MetadataField, ...] = ()
    recommendations: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
    relationships: tuple[tuple[str, str, str, str, float], ...] = ()
    provider_diagnostics: tuple[tuple[str, str, float, int], ...] = ()
    threat_history: tuple[str, ...] = ()
    performance: dict[str, float] = field(default_factory=dict)

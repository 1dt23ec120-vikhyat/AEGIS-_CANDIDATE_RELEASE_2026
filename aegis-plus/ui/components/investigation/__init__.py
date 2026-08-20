"""Reusable investigation workspace components.

Artifact-agnostic panels for the unified investigation workspace. Each component
renders a section from the :class:`InvestigationSummary` and adapts to whatever
artifact type populates the summary — no code branching per artifact.
"""

from ui.components.investigation.panels import (
    EvidenceTreePanel,
    InvestigationHeader,
    IOCPanel,
    MetadataPanel,
    PerformancePanel,
    ProviderDiagnosticsPanel,
    RecommendationsPanel,
    RelationshipPanel,
    ThreatHistoryPanel,
    TimelinePanel,
)

__all__ = [
    "EvidenceTreePanel",
    "IOCPanel",
    "InvestigationHeader",
    "MetadataPanel",
    "PerformancePanel",
    "ProviderDiagnosticsPanel",
    "RecommendationsPanel",
    "RelationshipPanel",
    "ThreatHistoryPanel",
    "TimelinePanel",
]

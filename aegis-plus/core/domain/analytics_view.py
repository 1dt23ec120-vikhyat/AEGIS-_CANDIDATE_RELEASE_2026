"""Graph analytics contracts (view DTOs).

Framework-free, immutable value objects produced by
:class:`services.analytics.graph_analytics.GraphAnalyticsService` and consumed by
delivery/UI layers. Like the graph view DTOs, they expose only display-ready
primitives and never the domain graph objects themselves. All analytics are
deterministic: rankings are ordered by score then id for stable output.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class RankedNode:
    """A node ranked by an analytics score (degree, centrality, risk)."""

    node_id: str
    node_type: str
    label: str
    score: float = 0.0
    degree: int = 0
    risk_percent: int = 0


@dataclass(frozen=True, slots=True)
class ComponentAnalysis:
    """Connected-component structure of the graph."""

    component_count: int = 0
    largest_size: int = 0
    sizes: tuple[int, ...] = ()
    isolated_count: int = 0


@dataclass(frozen=True, slots=True)
class BlastRadiusEstimate:
    """The set of nodes reachable from an origin (its blast radius)."""

    origin_id: str = ""
    reachable_count: int = 0
    reachable_ids: tuple[str, ...] = ()
    max_depth: int = 0


@dataclass(frozen=True, slots=True)
class ReachabilitySummary:
    """How far intelligence can spread from a node within a depth bound."""

    origin_id: str = ""
    reachable_count: int = 0
    max_depth: int = 0
    by_type: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class AttackPathView:
    """A candidate attack path between two nodes."""

    source_id: str = ""
    target_id: str = ""
    hops: int = 0
    node_ids: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Whether the path contains no nodes."""
        return not self.node_ids


@dataclass(frozen=True, slots=True)
class NeighborhoodAnalysis:
    """Multi-hop neighbourhood around a node."""

    origin_id: str = ""
    hops: int = 0
    node_count: int = 0
    edge_count: int = 0
    by_type: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class SharedInfrastructure:
    """Another node that shares infrastructure/IOCs with the origin."""

    origin_id: str = ""
    peer_id: str = ""
    peer_type: str = ""
    peer_label: str = ""
    shared_ids: tuple[str, ...] = ()

    @property
    def shared_count(self) -> int:
        """Number of shared infrastructure nodes."""
        return len(self.shared_ids)


@dataclass(frozen=True, slots=True)
class PropagationAnalysis:
    """Threat propagation from an origin across the graph."""

    origin_id: str = ""
    impacted_count: int = 0
    impacted_ids: tuple[str, ...] = ()
    threat_count: int = 0
    max_depth: int = 0


@dataclass(frozen=True, slots=True)
class GraphAnalyticsReport:
    """Aggregate analytics snapshot for dashboards and overviews."""

    node_count: int = 0
    edge_count: int = 0
    density: float = 0.0
    components: ComponentAnalysis = field(default_factory=ComponentAnalysis)
    top_degree: tuple[RankedNode, ...] = ()
    top_central: tuple[RankedNode, ...] = ()

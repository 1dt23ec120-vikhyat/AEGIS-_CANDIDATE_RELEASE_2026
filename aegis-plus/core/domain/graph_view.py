"""Graph presentation contracts (view DTOs).

Presentation-oriented, framework-free value objects that the Intelligence Graph
Explorer produces and the UI consumes. They deliberately expose only display-ready
primitives (identifiers, labels, tones, counts) and never the domain graph
objects themselves, so the presentation layer never manipulates
``core.domain.graph`` types directly.

Like :class:`core.domain.investigation.InvestigationSummary`, these live in
``core.domain`` because they are pure data shared by the producing service and
the consuming UI — no framework dependency, no I/O, no state.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class GraphNodeView:
    """A display-ready node."""

    node_id: str
    node_type: str
    label: str
    tone: str = "neutral"
    risk_percent: int = 0
    degree: int = 0
    labels: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GraphEdgeView:
    """A display-ready relationship."""

    edge_id: str
    source_id: str
    target_id: str
    relationship: str
    confidence: float = 1.0
    provenance: str = ""
    timestamp: str = ""


@dataclass(frozen=True, slots=True)
class GraphView:
    """A bounded subgraph ready for rendering."""

    root_id: str = ""
    nodes: tuple[GraphNodeView, ...] = ()
    edges: tuple[GraphEdgeView, ...] = ()
    truncated: bool = False

    @property
    def node_count(self) -> int:
        """Number of nodes in the view."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Number of edges in the view."""
        return len(self.edges)


@dataclass(frozen=True, slots=True)
class GraphSelection:
    """A focus node with its immediate neighbourhood identifiers.

    A lightweight selection descriptor the UI can use to highlight and pivot
    without re-fetching the whole view.
    """

    focus_id: str = ""
    neighbor_ids: tuple[str, ...] = ()
    edge_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GraphPathView:
    """A traversal path between two nodes."""

    source_id: str = ""
    target_id: str = ""
    found: bool = False
    length: int = 0
    nodes: tuple[GraphNodeView, ...] = ()
    edges: tuple[GraphEdgeView, ...] = ()


@dataclass(frozen=True, slots=True)
class GraphSnapshotView:
    """A point-in-time summary of the whole graph."""

    node_count: int = 0
    edge_count: int = 0
    duplicate_suppressions: int = 0
    node_type_counts: tuple[tuple[str, int], ...] = ()
    relationship_type_counts: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class ConnectedEntity:
    """A node paired with its connection count (for analytics)."""

    node: GraphNodeView
    degree: int


@dataclass(frozen=True, slots=True)
class GraphAnalyticsSummary:
    """Lightweight graph analytics for the Explorer overview."""

    node_count: int = 0
    edge_count: int = 0
    ioc_count: int = 0
    node_type_counts: tuple[tuple[str, int], ...] = ()
    relationship_type_counts: tuple[tuple[str, int], ...] = ()
    most_connected: tuple[ConnectedEntity, ...] = ()
    largest_component_size: int = 0
    component_count: int = 0
    reachable_from_top: int = 0
    density: float = 0.0


@dataclass(frozen=True, slots=True)
class GraphSearchResult:
    """The result of a graph search, with an auto-focus target."""

    query: str = ""
    focus_id: str = ""
    matches: tuple[GraphNodeView, ...] = ()

    @property
    def match_count(self) -> int:
        """Number of matches."""
        return len(self.matches)

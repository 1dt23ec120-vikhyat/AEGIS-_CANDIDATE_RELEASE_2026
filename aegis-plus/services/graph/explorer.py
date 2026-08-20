"""Graph Explorer service.

The application-layer capability that sits between the Knowledge Graph and the
future UI. It orchestrates the frozen :class:`GraphQueryService` (traversal and
query) and reuses :class:`IGraphRepository` for node enumeration, mapping domain
graph objects into presentation-oriented view DTOs. It reimplements no traversal
or query behaviour — every graph operation delegates to the query service or the
repository port.

The Explorer consumes the graph; it never owns it.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

from core.domain.graph import GraphEdge, GraphNode, NodeType
from core.domain.graph_view import (
    ConnectedEntity,
    GraphAnalyticsSummary,
    GraphEdgeView,
    GraphNodeView,
    GraphPathView,
    GraphSearchResult,
    GraphSelection,
    GraphSnapshotView,
    GraphView,
)
from core.interfaces import ILogger
from core.interfaces.graph_repository import IGraphRepository
from services.graph.query import GraphQueryService

_MAX_VIEW_NODES = 250
_COMPONENT_DEPTH = 10_000
_DEFAULT_SEARCH_LIMIT = 25
_DEFAULT_TOP_CONNECTED = 5

_F = TypeVar("_F", bound=Callable[..., Any])


def _tracked(method: _F) -> _F:
    """Record the wall-clock duration of a graph query for observability."""

    @wraps(method)
    def wrapper(self: GraphExplorerService, *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        try:
            return method(self, *args, **kwargs)
        finally:
            self._record_query((time.perf_counter() - start) * 1000)

    return cast(_F, wrapper)


_VERDICT_TONE = {
    "phishing": "danger",
    "malicious": "danger",
    "suspicious": "warning",
    "legitimate": "success",
    "benign": "success",
}
_TYPE_TONE = {
    NodeType.THREAT: "danger",
    NodeType.INCIDENT: "warning",
    NodeType.CAMPAIGN: "warning",
    NodeType.IOC: "warning",
}


class GraphExplorerService:
    """Application service for interactive knowledge-graph exploration."""

    def __init__(
        self,
        query: GraphQueryService,
        repository: IGraphRepository,
        logger: ILogger,
    ) -> None:
        """Initialize the explorer.

        Args:
            query: The frozen graph query service (traversal/query orchestration).
            repository: The graph repository port (reused for node enumeration).
            logger: Injected logger.
        """
        self._query = query
        self._repo = repository
        self._logger = logger
        self._query_count = 0
        self._query_ms_total = 0.0

    def _record_query(self, ms: float) -> None:
        self._query_count += 1
        self._query_ms_total += ms

    def metrics(self) -> dict[str, float]:
        """Backend query observability: count and durations."""
        avg = self._query_ms_total / self._query_count if self._query_count else 0.0
        return {
            "query_count": float(self._query_count),
            "total_query_ms": round(self._query_ms_total, 3),
            "avg_query_ms": round(avg, 3),
        }

    # --- overview --------------------------------------------------------

    @_tracked
    def snapshot(self) -> GraphSnapshotView:
        """Return a point-in-time summary of the whole graph."""
        snap = self._query.snapshot()
        return GraphSnapshotView(
            node_count=snap.node_count,
            edge_count=snap.edge_count,
            duplicate_suppressions=snap.duplicate_suppressions,
            node_type_counts=tuple(sorted(snap.node_type_counts.items())),
            relationship_type_counts=tuple(sorted(snap.relationship_type_counts.items())),
        )

    @_tracked
    def node(self, node_id: str) -> GraphNodeView | None:
        """Return a single node view, or ``None`` if it does not exist."""
        found = self._query.lookup(node_id)
        return self._node_view(found) if found is not None else None

    # --- exploration -----------------------------------------------------

    def neighbors(self, node_id: str) -> GraphView:
        """Return the focus node and its immediate neighbours (depth 1)."""
        return self.expand(node_id, depth=1)

    @_tracked
    def expand(self, node_id: str, *, depth: int = 1) -> GraphView:
        """Expand a node's neighbourhood up to ``depth`` hops.

        Delegates traversal to the query service; assembles a bounded view.
        """
        if self._query.lookup(node_id) is None:
            return GraphView(root_id=node_id)
        reachable = self._query.reachable(node_id, max_depth=max(1, depth))
        return self._view_from_nodes(node_id, reachable)

    @_tracked
    def selection(self, node_id: str) -> GraphSelection:
        """Return a lightweight selection descriptor for a focus node."""
        if self._query.lookup(node_id) is None:
            return GraphSelection(focus_id=node_id)
        neighbours = self._query.neighbors(node_id)
        edges = self._query.edges_of(node_id)
        return GraphSelection(
            focus_id=node_id,
            neighbor_ids=tuple(n.node_id for n in neighbours),
            edge_ids=tuple(e.edge_id for e in edges),
        )

    @_tracked
    def shortest_path(self, source_id: str, target_id: str) -> GraphPathView:
        """Return the shortest path between two nodes."""
        path = self._query.shortest_path(source_id, target_id)
        return GraphPathView(
            source_id=source_id,
            target_id=target_id,
            found=not path.is_empty and path.nodes[-1].node_id == target_id,
            length=path.length,
            nodes=tuple(self._node_view(n) for n in path.nodes),
            edges=tuple(self._edge_view(e) for e in path.edges),
        )

    @_tracked
    def shared_iocs(self, node_a_id: str, node_b_id: str) -> GraphView:
        """Return a view of two nodes and the IOCs they share."""
        shared = self._query.shared_iocs(node_a_id, node_b_id)
        anchors = [
            n
            for n in (self._query.lookup(node_a_id), self._query.lookup(node_b_id))
            if n is not None
        ]
        nodes = (*anchors, *shared)
        return self._view_from_nodes(node_a_id, nodes)

    @_tracked
    def investigation_graph(self, root_id: str, *, depth: int = 2) -> GraphView:
        """Return the subgraph reachable from an investigation root."""
        if self._query.lookup(root_id) is None:
            return GraphView(root_id=root_id)
        nodes = self._query.investigation_subgraph(root_id, max_depth=depth)
        return self._view_from_nodes(root_id, nodes)

    def incident_graph(self, incident_id: str) -> GraphView:
        """Return the neighbourhood of an incident node."""
        return self.expand(incident_id, depth=1)

    def campaign_graph(self, campaign_id: str) -> GraphView:
        """Return the neighbourhood of a campaign node."""
        return self.expand(campaign_id, depth=1)

    # --- search ----------------------------------------------------------

    @_tracked
    def search(self, query: str, *, limit: int = _DEFAULT_SEARCH_LIMIT) -> GraphSearchResult:
        """Search nodes by identifier, label, or metadata (case-insensitive)."""
        needle = query.strip().lower()
        if not needle:
            return GraphSearchResult(query=query)
        matches: list[GraphNodeView] = []
        for node in self._all_nodes():
            if self._matches(node, needle):
                matches.append(self._node_view(node))
                if len(matches) >= limit:
                    break
        focus = matches[0].node_id if matches else ""
        return GraphSearchResult(query=query, focus_id=focus, matches=tuple(matches))

    # --- analytics -------------------------------------------------------

    @_tracked
    def analytics(self, *, top: int = _DEFAULT_TOP_CONNECTED) -> GraphAnalyticsSummary:
        """Return lightweight graph analytics for the Explorer overview."""
        snap = self._query.snapshot()
        nodes = self._all_nodes()
        degrees = sorted(
            ((node, len(self._repo.edges_of(node.node_id))) for node in nodes),
            key=lambda pair: pair[1],
            reverse=True,
        )
        most_connected = tuple(
            ConnectedEntity(node=self._node_view(node, degree=degree), degree=degree)
            for node, degree in degrees[:top]
            if degree > 0
        )
        top_id = degrees[0][0].node_id if degrees else ""
        reachable_from_top = (
            len({n.node_id for n in self._query.reachable(top_id, max_depth=_COMPONENT_DEPTH)})
            if top_id
            else 0
        )
        components = self._query.connected_components()
        largest_component_size = max((len(c) for c in components), default=0)
        return GraphAnalyticsSummary(
            node_count=snap.node_count,
            edge_count=snap.edge_count,
            ioc_count=len(self._repo.nodes_by_type(NodeType.IOC)),
            node_type_counts=tuple(sorted(snap.node_type_counts.items())),
            relationship_type_counts=tuple(sorted(snap.relationship_type_counts.items())),
            most_connected=most_connected,
            largest_component_size=largest_component_size,
            component_count=len(components),
            reachable_from_top=reachable_from_top,
            density=self._query.graph_density(),
        )

    # --- helpers ---------------------------------------------------------

    def _all_nodes(self) -> tuple[GraphNode, ...]:
        """Enumerate every node across all types via the repository port."""
        collected: list[GraphNode] = []
        for node_type in NodeType:
            collected.extend(self._repo.nodes_by_type(node_type))
        return tuple(collected)

    def _view_from_nodes(self, root_id: str, nodes: tuple[GraphNode, ...]) -> GraphView:
        """Assemble a bounded :class:`GraphView` from a node set and its edges."""
        truncated = len(nodes) > _MAX_VIEW_NODES
        bounded = nodes[:_MAX_VIEW_NODES]
        ids = {n.node_id for n in bounded}
        node_views = tuple(self._node_view(n) for n in bounded)
        seen: set[str] = set()
        edge_views: list[GraphEdgeView] = []
        for node in bounded:
            for edge in self._repo.edges_of(node.node_id):
                if edge.edge_id in seen:
                    continue
                if edge.source_id in ids and edge.target_id in ids:
                    seen.add(edge.edge_id)
                    edge_views.append(self._edge_view(edge))
        return GraphView(
            root_id=root_id,
            nodes=node_views,
            edges=tuple(edge_views),
            truncated=truncated,
        )

    def _node_view(self, node: GraphNode, *, degree: int | None = None) -> GraphNodeView:
        """Map a domain node to a presentation node view."""
        deg = degree if degree is not None else len(self._repo.edges_of(node.node_id))
        return GraphNodeView(
            node_id=node.node_id,
            node_type=node.node_type.value,
            label=node.display_name or node.node_id,
            tone=self._tone(node),
            risk_percent=self._risk_percent(node),
            degree=deg,
            labels=node.labels,
            metadata=dict(node.metadata),
        )

    @staticmethod
    def _edge_view(edge: GraphEdge) -> GraphEdgeView:
        """Map a domain edge to a presentation edge view."""
        return GraphEdgeView(
            edge_id=edge.edge_id,
            source_id=edge.source_id,
            target_id=edge.target_id,
            relationship=edge.relationship.value,
            confidence=edge.confidence,
            provenance=edge.provenance,
            timestamp=edge.timestamp,
        )

    @staticmethod
    def _tone(node: GraphNode) -> str:
        """Derive a display tone from verdict metadata, then node type."""
        verdict = node.metadata.get("verdict", "").lower()
        if verdict in _VERDICT_TONE:
            return _VERDICT_TONE[verdict]
        return _TYPE_TONE.get(node.node_type, "neutral")

    @staticmethod
    def _risk_percent(node: GraphNode) -> int:
        """Derive a 0-100 risk from a ``risk_score`` metadata value, if present."""
        raw = node.metadata.get("risk_score", "")
        try:
            score = float(raw)
        except (TypeError, ValueError):
            return 0
        if score <= 1.0:
            score *= 100
        return max(0, min(100, round(score)))

    @staticmethod
    def _matches(node: GraphNode, needle: str) -> bool:
        """Whether a node matches a lowercased search needle."""
        if needle in node.node_id.lower() or needle in node.display_name.lower():
            return True
        if any(needle in label.lower() for label in node.labels):
            return True
        return any(needle in value.lower() for value in node.metadata.values())

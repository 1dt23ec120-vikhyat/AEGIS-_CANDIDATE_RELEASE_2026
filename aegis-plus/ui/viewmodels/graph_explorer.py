"""Graph Explorer view-model.

The MVVM view-model for the Intelligence Graph Explorer. It owns presentation
state (the loaded graph, current filters, timeline cutoff, selection), performs
all backend access through :class:`BackendClient` on a worker thread, applies
client-side filtering/timeline focus, and exposes everything to the page through
Qt signals. It never touches graph repositories or domain objects directly.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import QObject, Signal

from core.domain.graph_view import (
    GraphAnalyticsSummary,
    GraphEdgeView,
    GraphNodeView,
    GraphSearchResult,
    GraphSnapshotView,
    GraphView,
)
from core.domain.soc_analytics_view import GraphOverlay
from ui.backend import AsyncRunner, BackendClient
from ui.components.graph.panels import FilterCriteria
from ui.viewmodels.base import ViewModel
from ui.viewmodels.explorer_session import ExplorerSessionState, ViewportState

_DEFAULT_DEPTH = 1

RunnerFactory = Callable[[QObject], AsyncRunner]


@dataclass(frozen=True, slots=True)
class _Overview:
    snapshot: GraphSnapshotView
    analytics: GraphAnalyticsSummary


@dataclass(frozen=True, slots=True)
class _GraphResult:
    view: GraphView
    merge: bool
    focus: str
    latency_ms: float


class GraphExplorerViewModel(ViewModel):
    """Presentation state and backend orchestration for the Graph Explorer."""

    snapshot_ready = Signal(object)  # GraphSnapshotView
    analytics_ready = Signal(object)  # GraphAnalyticsSummary
    graph_ready = Signal(object)  # GraphView (full, pre-filter)
    focus_requested = Signal(str)  # node id to centre on
    visibility_changed = Signal(object, object)  # (visible_node_ids, visible_edge_ids)
    node_details = Signal(object)  # GraphNodeView | None
    edge_details = Signal(object)  # GraphEdgeView | None
    search_ready = Signal(object)  # GraphSearchResult
    busy_changed = Signal(bool)
    error = Signal(str)
    expand_metric = Signal(float)  # expansion latency ms
    metrics_ready = Signal(object)  # dict[str, float] — full observability set
    overlay_ready = Signal(object)  # GraphOverlay — analytics overlay annotations

    def __init__(
        self,
        client: BackendClient,
        *,
        runner_factory: RunnerFactory = AsyncRunner,
    ) -> None:
        """Initialize the view-model.

        Args:
            client: Backend gateway for graph queries.
            runner_factory: Builds the workers that run backend calls off the UI
                thread. Defaults to the threaded :class:`AsyncRunner`; tests can
                inject a synchronous runner for deterministic execution.
        """
        super().__init__()
        self._client = client
        self._overview_runner = runner_factory(self)
        self._overview_runner.finished.connect(self._on_overview)
        self._graph_runner = runner_factory(self)
        self._graph_runner.finished.connect(self._on_graph)
        self._search_runner = runner_factory(self)
        self._search_runner.finished.connect(self._on_search)
        self._overlay_runner = runner_factory(self)
        self._overlay_runner.finished.connect(self._on_overlay)

        self._current: GraphView = GraphView()
        self._filters = FilterCriteria()
        self._cutoff = ""
        self._metrics: dict[str, float] = {}
        self._search_started = 0.0
        self._expansion_count = 0
        self._focus_node = ""
        self._expanded_nodes: set[str] = set()
        self._depth = _DEFAULT_DEPTH

    @property
    def current_view(self) -> GraphView:
        """The full loaded graph view (before client-side filtering)."""
        return self._current

    # --- loading ---------------------------------------------------------

    def load_overview(self) -> None:
        """Load the graph snapshot and analytics summary."""
        self.busy_changed.emit(True)
        self._overview_runner.run(
            lambda: _Overview(self._client.graph_snapshot(), self._client.graph_analytics())
        )

    def load_neighbors(self, node_id: str, *, depth: int = _DEFAULT_DEPTH) -> None:
        """Load a node's neighbourhood and replace the current view."""
        self._focus_node = node_id
        self._depth = depth
        self._publish_metrics(expansion_depth=depth)
        self._dispatch_graph(
            lambda: self._client.graph_neighbors(node_id, depth=depth),
            merge=False,
            focus=node_id,
        )

    def focus(self, node_id: str) -> None:
        """Focus a node: centre on it if loaded, else load its neighbourhood."""
        self._focus_node = node_id
        if node_id in {n.node_id for n in self._current.nodes}:
            self.focus_requested.emit(node_id)
            self.select_node(node_id)
        else:
            self.load_neighbors(node_id)

    def expand(self, node_id: str, *, depth: int = _DEFAULT_DEPTH) -> None:
        """Expand a node in place, merging its neighbourhood into the view."""
        self._expansion_count += 1
        self._expanded_nodes.add(node_id)
        self._depth = depth
        self._publish_metrics(expansion_depth=depth, expansion_count=self._expansion_count)
        self._dispatch_graph(
            lambda: self._client.graph_neighbors(node_id, depth=depth),
            merge=True,
            focus=node_id,
        )

    def shortest_path(self, source_id: str, target_id: str) -> None:
        """Load the shortest path between two nodes as the current view."""
        self._dispatch_graph(
            lambda: self._path_as_view(source_id, target_id), merge=False, focus=source_id
        )

    def shared_iocs(self, node_a_id: str, node_b_id: str) -> None:
        """Load the shared-IOC view for two nodes."""
        self._dispatch_graph(
            lambda: self._client.graph_shared_iocs(node_a_id, node_b_id),
            merge=False,
            focus=node_a_id,
        )

    def investigation(self, root_id: str, *, depth: int = 2) -> None:
        """Load an investigation subgraph."""
        self._dispatch_graph(
            lambda: self._client.graph_investigation(root_id, depth=depth),
            merge=False,
            focus=root_id,
        )

    def incident(self, incident_id: str) -> None:
        """Load an incident's neighbourhood."""
        self._dispatch_graph(
            lambda: self._client.graph_incident(incident_id), merge=False, focus=incident_id
        )

    def campaign(self, campaign_id: str) -> None:
        """Load a campaign's neighbourhood."""
        self._dispatch_graph(
            lambda: self._client.graph_campaign(campaign_id), merge=False, focus=campaign_id
        )

    def search(self, query: str) -> None:
        """Run a graph search."""
        self._search_started = time.perf_counter()
        self._search_runner.run(lambda: self._client.graph_search(query))

    # --- selection -------------------------------------------------------

    def select_node(self, node_id: str) -> None:
        """Emit details for a node in the current view."""
        match = next((n for n in self._current.nodes if n.node_id == node_id), None)
        self.node_details.emit(match)
        if match is not None:
            self.edge_details.emit(None)

    def select_edge(self, edge_id: str) -> None:
        """Emit details for an edge in the current view."""
        match = next((e for e in self._current.edges if e.edge_id == edge_id), None)
        self.edge_details.emit(match)
        if match is not None:
            self.node_details.emit(None)

    def clear_selection(self) -> None:
        """Clear the current node/edge selection."""
        self.node_details.emit(None)
        self.edge_details.emit(None)

    # --- filtering & timeline -------------------------------------------

    def set_filters(self, criteria: FilterCriteria) -> None:
        """Apply node/relationship/confidence filters."""
        self._filters = criteria
        self._emit_visibility()

    def set_cutoff(self, cutoff: str) -> None:
        """Apply a timeline cutoff (empty string shows all)."""
        self._cutoff = cutoff
        self._emit_visibility()

    def session_state(self, viewport: ViewportState | None = None) -> ExplorerSessionState:
        """Capture the current session as an in-memory value object.

        Presentation-only: no persistence. A future milestone can serialise this.
        """
        return ExplorerSessionState(
            focus_node=self._focus_node,
            expanded_nodes=frozenset(self._expanded_nodes),
            filters=self._filters,
            timeline_cutoff=self._cutoff,
            depth=self._depth,
            viewport=viewport or ViewportState(),
        )

    def restore_session(self, state: ExplorerSessionState) -> None:
        """Restore filters, cutoff, focus, and expansion depth from a session.

        The graph itself is re-focused via :attr:`focus_requested`; durable
        re-fetching of expanded nodes is intentionally left to a future
        persistence milestone.
        """
        self._filters = state.filters
        self._cutoff = state.timeline_cutoff
        self._depth = state.depth
        self._focus_node = state.focus_node
        self._expanded_nodes = set(state.expanded_nodes)
        self._emit_visibility()
        if state.focus_node:
            self.focus_requested.emit(state.focus_node)

    def available_node_types(self) -> list[str]:
        """Node types present in the current view (for filter controls)."""
        return sorted({n.node_type for n in self._current.nodes})

    def available_relationships(self) -> list[str]:
        """Relationship types present in the current view (for filter controls)."""
        return sorted({e.relationship for e in self._current.edges})

    def timestamps(self) -> list[str]:
        """Distinct edge timestamps present in the current view (for the timeline)."""
        return sorted({e.timestamp for e in self._current.edges if e.timestamp})

    def _emit_visibility(self) -> None:
        started = time.perf_counter()
        visible_nodes = {
            n.node_id for n in self._current.nodes if self._filters.allows_node(n.node_type)
        }
        visible_edges = {
            e.edge_id
            for e in self._current.edges
            if e.source_id in visible_nodes
            and e.target_id in visible_nodes
            and self._filters.allows_edge(e.relationship, e.confidence)
            and (not self._cutoff or not e.timestamp or e.timestamp <= self._cutoff)
        }
        elapsed = (time.perf_counter() - started) * 1000
        total = self._current.node_count
        self._publish_metrics(
            timeline_ms=elapsed,
            visible_node_count=len(visible_nodes),
            hidden_node_count=max(total - len(visible_nodes), 0),
        )
        self.visibility_changed.emit(visible_nodes, visible_edges)

    # --- workers ---------------------------------------------------------

    def _path_as_view(self, source_id: str, target_id: str) -> GraphView:
        path = self._client.graph_shortest_path(source_id, target_id)
        edges = tuple(path.edges)
        return GraphView(root_id=source_id, nodes=tuple(path.nodes), edges=edges, truncated=False)

    def _dispatch_graph(
        self,
        worker: object,
        *,
        merge: bool,
        focus: str,
    ) -> None:
        self.busy_changed.emit(True)
        started = time.perf_counter()

        def run() -> _GraphResult:
            view = worker()  # type: ignore[operator]
            latency = (time.perf_counter() - started) * 1000
            return _GraphResult(view=view, merge=merge, focus=focus, latency_ms=latency)

        self._graph_runner.run(run)

    def _on_overview(self, result: object) -> None:
        self.busy_changed.emit(False)
        if not isinstance(result, _Overview):
            return
        self.snapshot_ready.emit(result.snapshot)
        self.analytics_ready.emit(result.analytics)

    def _on_graph(self, result: object) -> None:
        self.busy_changed.emit(False)
        if not isinstance(result, _GraphResult):
            return
        view = _merge_views(self._current, result.view) if result.merge else result.view
        self._current = view
        if not view.nodes:
            self.error.emit("No graph data for this selection.")
        self.graph_ready.emit(view)
        self.expand_metric.emit(round(result.latency_ms, 1))
        updates = {
            "query_ms": result.latency_ms,
            "node_count": float(view.node_count),
            "edge_count": float(view.edge_count),
            "visible_node_count": float(view.node_count),
            "hidden_node_count": 0.0,
        }
        if result.merge:
            updates["expand_ms"] = result.latency_ms
        self._publish_metrics(**updates)
        self._filters = FilterCriteria()
        self._cutoff = ""
        if result.focus:
            self.focus_requested.emit(result.focus)

    def _on_search(self, result: object) -> None:
        if isinstance(result, GraphSearchResult):
            self._publish_metrics(search_ms=(time.perf_counter() - self._search_started) * 1000)
            self.search_ready.emit(result)

    def load_overlay(self, *, top: int = 10) -> None:
        """Fetch the analytics overlay (critical nodes, attack paths, risk)."""
        self._overlay_runner.run(lambda: self._client.graph_overlay(top=top))

    def _on_overlay(self, result: object) -> None:
        if isinstance(result, GraphOverlay):
            self.overlay_ready.emit(result)

    def _publish_metrics(self, **updates: float) -> None:
        """Merge observability updates into the metric set and emit them."""
        self._metrics.update(updates)
        self.metrics_ready.emit(dict(self._metrics))


def _merge_views(base: GraphView, addition: GraphView) -> GraphView:
    """Union two graph views, de-duplicating nodes and edges by id."""
    nodes: dict[str, GraphNodeView] = {n.node_id: n for n in base.nodes}
    for node in addition.nodes:
        nodes[node.node_id] = node
    edges: dict[str, GraphEdgeView] = {e.edge_id: e for e in base.edges}
    for edge in addition.edges:
        edges[edge.edge_id] = edge
    return GraphView(
        root_id=base.root_id or addition.root_id,
        nodes=tuple(nodes.values()),
        edges=tuple(edges.values()),
        truncated=base.truncated or addition.truncated,
    )

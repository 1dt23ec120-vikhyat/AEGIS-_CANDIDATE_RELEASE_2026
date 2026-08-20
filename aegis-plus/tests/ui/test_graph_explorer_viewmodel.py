"""Tests for the Graph Explorer view-model (M9-P3-B).

Backend calls run through an injected synchronous runner, so each operation
completes inline; assertions can inspect emitted signals and state directly.
"""

from __future__ import annotations

import pytest

from core.domain.graph_view import (
    ConnectedEntity,
    GraphAnalyticsSummary,
    GraphEdgeView,
    GraphNodeView,
    GraphPathView,
    GraphSearchResult,
    GraphSnapshotView,
    GraphView,
)
from tests.ui._async import SyncRunner
from ui.backend import BackendClient
from ui.components.graph.panels import FilterCriteria
from ui.viewmodels.graph_explorer import GraphExplorerViewModel

pytestmark = pytest.mark.ui

_A = GraphNodeView("a", "url", "http://evil.example", tone="danger", risk_percent=90, degree=2)
_B = GraphNodeView("b", "file", "invoice.docm", tone="neutral", degree=1)
_C = GraphNodeView("c", "incident", "Phishing wave", tone="warning", degree=1)
_D = GraphNodeView("d", "domain", "evil.example", tone="neutral", degree=1)
_E_AB = GraphEdgeView("e-ab", "a", "b", "related_to", confidence=0.9, timestamp="2026-01-01T00:00")
_E_CD = GraphEdgeView("e-cd", "c", "d", "part_of", confidence=0.6, timestamp="2026-02-01T00:00")


class _FakeClient(BackendClient):
    def __init__(self) -> None:
        super().__init__("http://127.0.0.1:9")

    def graph_snapshot(self) -> GraphSnapshotView:
        return GraphSnapshotView(node_count=4, edge_count=2)

    def graph_analytics(self, *, top: int = 5) -> GraphAnalyticsSummary:
        return GraphAnalyticsSummary(
            node_count=4,
            edge_count=2,
            ioc_count=0,
            most_connected=(ConnectedEntity(node=_A, degree=2),),
            largest_component_size=2,
        )

    def graph_neighbors(self, node_id: str, *, depth: int = 1) -> GraphView:
        if node_id == "c":
            return GraphView(root_id="c", nodes=(_C, _D), edges=(_E_CD,))
        return GraphView(root_id=node_id, nodes=(_A, _B), edges=(_E_AB,))

    def graph_search(self, query: str, *, limit: int = 25) -> GraphSearchResult:
        return GraphSearchResult(query=query, focus_id="a", matches=(_A,))

    def graph_shortest_path(self, source_id: str, target_id: str) -> GraphPathView:
        return GraphPathView(
            source_id=source_id,
            target_id=target_id,
            found=True,
            length=1,
            nodes=(_A, _B),
            edges=(_E_AB,),
        )


def _vm() -> GraphExplorerViewModel:
    return GraphExplorerViewModel(_FakeClient(), runner_factory=SyncRunner)


def test_load_overview_emits_snapshot_and_analytics(qapp: object) -> None:
    vm = _vm()
    snaps: list[GraphSnapshotView] = []
    analytics: list[GraphAnalyticsSummary] = []
    vm.snapshot_ready.connect(snaps.append)
    vm.analytics_ready.connect(analytics.append)
    vm.load_overview()
    assert snaps[0].node_count == 4
    assert analytics[0].node_count == 4


def test_load_neighbors_emits_graph_focus_and_metric(qapp: object) -> None:
    vm = _vm()
    graphs: list[GraphView] = []
    focuses: list[str] = []
    metrics: list[float] = []
    vm.graph_ready.connect(graphs.append)
    vm.focus_requested.connect(focuses.append)
    vm.expand_metric.connect(metrics.append)
    vm.load_neighbors("a")
    assert {n.node_id for n in graphs[0].nodes} == {"a", "b"}
    assert focuses and focuses[0] == "a"
    assert bool(metrics)


def test_expand_merges_into_current_view(qapp: object) -> None:
    vm = _vm()
    vm.load_neighbors("a")
    vm.expand("c")
    merged = vm.current_view
    assert {n.node_id for n in merged.nodes} == {"a", "b", "c", "d"}
    assert {e.edge_id for e in merged.edges} == {"e-ab", "e-cd"}


def test_search_emits_results(qapp: object) -> None:
    vm = _vm()
    results: list[GraphSearchResult] = []
    vm.search_ready.connect(results.append)
    vm.search("evil")
    assert results[0].focus_id == "a"
    assert results[0].match_count == 1


def test_select_node_and_edge(qapp: object) -> None:
    vm = _vm()
    vm.load_neighbors("a")
    nodes: list[GraphNodeView] = []
    vm.node_details.connect(nodes.append)
    vm.select_node("a")
    assert nodes[0].node_id == "a"
    edges: list[GraphEdgeView] = []
    vm.edge_details.connect(edges.append)
    vm.select_edge("e-ab")
    assert edges[0].edge_id == "e-ab"


def test_filters_change_visibility(qapp: object) -> None:
    vm = _vm()
    vm.load_neighbors("a")
    captured: list[tuple[set[str], set[str]]] = []

    def _cap(nodes: set[str], edges: set[str]) -> None:
        captured.append((nodes, edges))

    vm.visibility_changed.connect(_cap)
    vm.set_filters(FilterCriteria(node_types=frozenset({"url"})))
    visible_nodes, visible_edges = captured[0]
    assert "a" in visible_nodes and "b" not in visible_nodes
    assert "e-ab" not in visible_edges


def test_cutoff_hides_later_edges(qapp: object) -> None:
    vm = _vm()
    vm.load_neighbors("c")
    captured: list[tuple[set[str], set[str]]] = []

    def _cap(nodes: set[str], edges: set[str]) -> None:
        captured.append((nodes, edges))

    vm.visibility_changed.connect(_cap)
    vm.set_cutoff("2026-01-15T00:00")
    _, visible_edges = captured[0]
    assert "e-cd" not in visible_edges


def test_available_types_and_timestamps(qapp: object) -> None:
    vm = _vm()
    vm.load_neighbors("c")
    assert vm.available_node_types() == ["domain", "incident"]
    assert vm.available_relationships() == ["part_of"]
    assert vm.timestamps() == ["2026-02-01T00:00"]


def test_shortest_path_loads_view(qapp: object) -> None:
    vm = _vm()
    graphs: list[GraphView] = []
    vm.graph_ready.connect(graphs.append)
    vm.shortest_path("a", "b")
    assert {n.node_id for n in graphs[0].nodes} == {"a", "b"}


def test_metrics_ready_emits_observability(qapp: object) -> None:
    vm = _vm()
    metrics: list[dict[str, float]] = []
    vm.metrics_ready.connect(metrics.append)
    vm.load_neighbors("a", depth=2)
    latest = metrics[-1]
    assert latest["expansion_depth"] == 2.0
    assert latest["node_count"] == 2.0
    assert "query_ms" in latest
    vm.expand("c")
    assert metrics[-1]["expansion_count"] == 1.0
    assert "expand_ms" in metrics[-1]
    vm.set_cutoff("2026-01-15T00:00")
    assert "timeline_ms" in metrics[-1]
    assert "visible_node_count" in metrics[-1]
    vm.search("evil")
    assert "search_ms" in metrics[-1]


def test_session_capture_and_restore(qapp: object) -> None:
    from ui.viewmodels.explorer_session import ExplorerSessionState, ViewportState

    vm = _vm()
    vm.load_neighbors("a", depth=3)
    vm.expand("c", depth=3)
    vm.set_filters(FilterCriteria(node_types=frozenset({"url"})))
    vm.set_cutoff("2026-02-01T00:00")
    state = vm.session_state(ViewportState(scale=1.5, center_x=10.0, center_y=20.0))
    assert isinstance(state, ExplorerSessionState)
    assert state.focus_node == "a"
    assert "c" in state.expanded_nodes
    assert state.depth == 3
    assert state.timeline_cutoff == "2026-02-01T00:00"
    assert state.viewport.scale == 1.5
    assert not state.is_empty

    # Restore into a fresh view-model: filters/cutoff/focus are re-applied.
    other = _vm()
    other.load_neighbors("a")
    focuses: list[str] = []
    vis: list[tuple[set[str], set[str]]] = []
    other.focus_requested.connect(focuses.append)
    other.visibility_changed.connect(lambda n, e: vis.append((n, e)))
    other.restore_session(state)
    assert focuses[-1] == "a"
    assert vis  # visibility recomputed


def test_load_overlay_emits_overlay(qapp: object) -> None:
    from core.domain.soc_analytics_view import GraphOverlay, NodeOverlay

    class _OverlayClient(_FakeClient):
        def graph_overlay(self, *, top: int = 10) -> GraphOverlay:
            return GraphOverlay(
                nodes=(NodeOverlay(node_id="a", is_critical=True),),
                critical_ids=("a",),
                attack_path_ids=("a", "b"),
            )

    vm = GraphExplorerViewModel(_OverlayClient(), runner_factory=SyncRunner)
    received: list[GraphOverlay] = []
    vm.overlay_ready.connect(received.append)
    vm.load_overlay(top=10)
    assert received
    assert received[-1].critical_ids == ("a",)
    assert "b" in received[-1].attack_path_ids

"""Tests for the Graph Explorer page (M9-P3-B)."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QLabel, QWidget

from core.domain.graph_view import (
    GraphAnalyticsSummary,
    GraphEdgeView,
    GraphNodeView,
    GraphSnapshotView,
    GraphView,
)
from tests.ui._async import SyncRunner
from ui.backend import BackendClient
from ui.context import UIContext
from ui.navigation import Route
from ui.pages.graph_explorer import GraphExplorerPage
from ui.theme import ThemeManager, ThemeMode
from ui.viewmodels.graph_explorer import _GraphResult

pytestmark = pytest.mark.ui

_VIEW = GraphView(
    root_id="a",
    nodes=(
        GraphNodeView("a", "url", "http://evil.example", tone="danger", risk_percent=90),
        GraphNodeView("b", "file", "invoice.docm"),
        GraphNodeView("c", "incident", "Phishing wave", tone="warning"),
    ),
    edges=(GraphEdgeView("e-ab", "a", "b", "related_to", confidence=0.9),),
)


class _FakeClient(BackendClient):
    """No-network client so async tasks finish instantly in tests."""

    def __init__(self) -> None:
        super().__init__("http://127.0.0.1:9")

    def graph_snapshot(self) -> GraphSnapshotView:
        return GraphSnapshotView(node_count=3, edge_count=1)

    def graph_analytics(self, *, top: int = 5) -> GraphAnalyticsSummary:
        return GraphAnalyticsSummary(node_count=3, edge_count=1)

    def graph_neighbors(self, node_id: str, *, depth: int = 1) -> GraphView:
        return _VIEW


def _text(widget: QWidget) -> str:
    return " | ".join(lbl.text() for lbl in widget.findChildren(QLabel) if lbl.text())


class _Nav:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object]] = []

    def __call__(self, route: object, payload: object = None) -> None:
        self.calls.append((route, payload))


def _page(nav: _Nav | None = None) -> GraphExplorerPage:
    context = UIContext(
        theme_manager=ThemeManager(ThemeMode.DARK),
        backend_client=_FakeClient(),
        navigate=nav,
    )
    return GraphExplorerPage(context, runner_factory=SyncRunner)


def _load(page: GraphExplorerPage) -> None:
    """Synchronously seed the view-model's current view and render it."""
    page._vm._on_graph(_GraphResult(view=_VIEW, merge=False, focus="", latency_ms=1.0))


def test_page_builds(qapp: object) -> None:
    page = _page()
    assert page._canvas is not None
    assert page._search is not None
    assert page._analytics is not None


def test_graph_ready_renders_canvas(qapp: object) -> None:
    page = _page()
    _load(page)
    assert set(page._canvas.node_items) == {"a", "b", "c"}
    assert page._hint.isHidden()


def test_on_navigated_shows_back(qapp: object) -> None:
    page = _page()
    page.on_navigated({"focus": "a", "origin": Route.FILE_SCANNER})
    assert not page._back.isHidden()
    assert page._origin == Route.FILE_SCANNER


def test_on_navigated_ignores_bad_payload(qapp: object) -> None:
    page = _page()
    page.on_navigated("not-a-dict")
    assert page._back.isHidden()


def test_back_navigates_to_origin(qapp: object) -> None:
    nav = _Nav()
    page = _page(nav)
    page.on_navigated({"focus": "a", "origin": Route.FILE_SCANNER})
    page._go_back()
    assert nav.calls[-1][0] == Route.FILE_SCANNER


def test_open_investigation_routes_by_type(qapp: object) -> None:
    nav = _Nav()
    page = _page(nav)
    _load(page)
    page._open_investigation("c")  # incident -> Incidents
    incident_route = nav.calls[-1][0]
    page._open_investigation("b")  # file -> File Scanner
    file_route = nav.calls[-1][0]
    assert incident_route == Route.INCIDENTS
    assert file_route == Route.FILE_SCANNER


def test_node_details_render(qapp: object) -> None:
    page = _page()
    _load(page)
    page._vm.node_details.emit(_VIEW.nodes[0])
    assert "evil.example" in _text(page._node_details)


def test_page_session_capture_and_restore(qapp: object) -> None:
    from ui.viewmodels.explorer_session import ExplorerSessionState

    page = _page()
    _load(page)
    page._vm.expand("c")
    state = page.session_state()
    assert isinstance(state, ExplorerSessionState)
    # Restoring the captured session does not raise and re-applies it.
    page.restore_session(state)

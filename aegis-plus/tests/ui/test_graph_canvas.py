"""Tests for the interactive graph canvas (M9-P3-B)."""

from __future__ import annotations

import pytest
from PySide6.QtTest import QSignalSpy

from core.domain.graph_view import GraphEdgeView, GraphNodeView, GraphView
from ui.components.graph.canvas import GraphCanvas
from ui.components.graph.items import GraphEdgeItem, GraphNodeItem
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui

_NODES = (
    GraphNodeView("a", "url", "http://evil.example", tone="danger", risk_percent=90),
    GraphNodeView("b", "file", "invoice.docm"),
    GraphNodeView("c", "incident", "Phishing wave", tone="warning"),
)
_EDGES = (
    GraphEdgeView("e-ab", "a", "b", "related_to", confidence=0.9),
    GraphEdgeView("e-ac", "a", "c", "part_of", confidence=0.7),
)
_VIEW = GraphView(root_id="a", nodes=_NODES, edges=_EDGES)


def _canvas() -> GraphCanvas:
    return GraphCanvas(ThemeManager(ThemeMode.DARK))


def test_set_graph_populates_items_and_emits_metrics(qapp: object) -> None:
    canvas = _canvas()
    spy = QSignalSpy(canvas.metrics)
    canvas.set_graph(_VIEW)
    assert set(canvas.node_items) == {"a", "b", "c"}
    assert len(canvas.edge_items) == 2
    assert spy.count() >= 1
    metrics = spy.at(0)[0]
    assert metrics["node_count"] == 3.0
    assert metrics["edge_count"] == 2.0
    assert "layout_ms" in metrics and "render_ms" in metrics


def test_clear_removes_items(qapp: object) -> None:
    canvas = _canvas()
    canvas.set_graph(_VIEW)
    canvas.clear()
    assert canvas.node_items == {}
    assert canvas.edge_items == []


def test_highlight_nodes_thickens_pen(qapp: object) -> None:
    canvas = _canvas()
    canvas.set_graph(_VIEW)
    canvas.highlight_nodes(["a"])
    assert canvas.node_items["a"].pen().widthF() == pytest.approx(3.0)
    assert canvas.node_items["b"].pen().widthF() == pytest.approx(1.5)
    canvas.clear_highlight()
    assert canvas.node_items["a"].pen().widthF() == pytest.approx(1.5)


def test_set_visible_dims_others(qapp: object) -> None:
    canvas = _canvas()
    canvas.set_graph(_VIEW)
    canvas.set_visible({"a"}, set())
    assert canvas.node_items["a"].opacity() == pytest.approx(1.0)
    assert canvas.node_items["b"].opacity() == pytest.approx(0.25)
    assert canvas.edge_items[0].opacity() == pytest.approx(0.15)
    canvas.reset_visibility()
    assert canvas.node_items["b"].opacity() == pytest.approx(1.0)


def test_zoom_changes_scale(qapp: object) -> None:
    canvas = _canvas()
    canvas.set_graph(_VIEW)
    canvas.fit()
    before = canvas.transform().m11()
    canvas.zoom_in()
    assert canvas.transform().m11() > before


def test_focus_node_selects(qapp: object) -> None:
    canvas = _canvas()
    canvas.set_graph(_VIEW)
    canvas.focus_node("a")
    assert canvas.node_items["a"].isSelected()


def test_edges_track_node_movement(qapp: object) -> None:
    canvas = _canvas()
    canvas.set_graph(_VIEW)
    edge = canvas.edge_items[0]
    node_a = canvas.node_items["a"]
    node_a.setPos(node_a.pos().x() + 50, node_a.pos().y() + 50)
    # itemChange -> _reposition_edges keeps the edge line attached to the node.
    assert edge.line().x1() == pytest.approx(node_a.pos().x())
    assert edge.line().y1() == pytest.approx(node_a.pos().y())


def test_node_and_edge_item_helpers(qapp: object) -> None:
    canvas = _canvas()
    canvas.set_graph(_VIEW)
    node = canvas.node_items["a"]
    assert isinstance(node, GraphNodeItem)
    node.set_highlighted(True)
    node.set_dimmed(True)
    assert node.opacity() == pytest.approx(0.25)
    edge = canvas.edge_items[0]
    assert isinstance(edge, GraphEdgeItem)
    assert edge.endpoints() == ("a", "b")


def test_keyboard_zoom_and_fit(qapp: object) -> None:
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent

    canvas = _canvas()
    canvas.set_graph(_VIEW)
    canvas.fit()
    before = canvas.transform().m11()

    def _key(key: Qt.Key) -> QKeyEvent:
        return QKeyEvent(QEvent.Type.KeyPress, key, Qt.KeyboardModifier.NoModifier)

    canvas.keyPressEvent(_key(Qt.Key.Key_Plus))
    assert canvas.transform().m11() > before
    zoomed = canvas.transform().m11()
    canvas.keyPressEvent(_key(Qt.Key.Key_Minus))
    assert canvas.transform().m11() < zoomed
    # Arrow keys pan without raising.
    canvas.keyPressEvent(_key(Qt.Key.Key_Right))
    canvas.keyPressEvent(_key(Qt.Key.Key_Down))
    canvas.keyPressEvent(_key(Qt.Key.Key_F))  # fit


def test_viewport_capture_and_restore(qapp: object) -> None:
    canvas = _canvas()
    canvas.set_graph(_VIEW)
    canvas.apply_viewport(2.0, 15.0, 25.0)
    assert canvas.viewport_scale() == pytest.approx(2.0, abs=0.01)
    cx, cy = canvas.viewport_center()
    assert isinstance(cx, float) and isinstance(cy, float)

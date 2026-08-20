"""Interactive graph canvas.

A :class:`QGraphicsView` that renders a :class:`GraphView`, laying it out with a
deterministic spring model. Supports pan, zoom, node drag, fit-to-view, focus,
hover relationship highlighting, and visibility filtering. Emits selection and
expansion intents plus render/layout timing for observability.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QKeyEvent, QMouseEvent, QPainter, QWheelEvent
from PySide6.QtWidgets import QGraphicsScene, QGraphicsView, QWidget

from core.domain.graph_view import GraphView
from ui.components.graph.identity import node_identity
from ui.components.graph.items import GraphEdgeItem, GraphNodeItem
from ui.components.graph.layout import spring_layout
from ui.theme import ThemeManager

_ZOOM_STEP = 1.15
_MIN_SCALE = 0.2
_MAX_SCALE = 4.0
_FIT_MARGIN = 60
_KEY_PAN_STEP = 60


class GraphCanvas(QGraphicsView):
    """Renders and lets analysts explore a graph view."""

    node_clicked = Signal(str)
    edge_clicked = Signal(str)
    node_expand_requested = Signal(str)
    background_clicked = Signal()
    metrics = Signal(object)  # dict[str, float]

    def __init__(self, theme_manager: ThemeManager, *, parent: QWidget | None = None) -> None:
        """Build the canvas."""
        super().__init__(parent)
        self._theme = theme_manager
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.setDragMode(QGraphicsView.DragMode.NoDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setMinimumHeight(420)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        self._nodes: dict[str, GraphNodeItem] = {}
        self._edges: list[GraphEdgeItem] = []
        self._adjacency: dict[str, set[str]] = {}
        self._panning = False
        self._pan_start: tuple[float, float] = (0.0, 0.0)
        self._scale = 1.0

    # --- rendering -------------------------------------------------------

    def set_graph(self, view: GraphView) -> None:
        """Render a graph view, laying it out and reporting timing."""
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()
        self._adjacency = {n.node_id: set() for n in view.nodes}

        layout_start = time.perf_counter()
        positions = spring_layout(
            [n.node_id for n in view.nodes],
            [(e.source_id, e.target_id) for e in view.edges],
        )
        layout_ms = (time.perf_counter() - layout_start) * 1000

        render_start = time.perf_counter()
        palette = self._theme.theme.palette
        for node in view.nodes:
            item = GraphNodeItem(
                node,
                node_identity(node.node_type, palette),
                on_moved=self._reposition_edges,
                on_hover=self._on_hover,
                on_clicked=self.node_clicked.emit,
            )
            x, y = positions.get(node.node_id, (0.0, 0.0))
            item.setPos(x, y)
            self._scene.addItem(item)
            self._nodes[node.node_id] = item

        for edge in view.edges:
            source = self._nodes.get(edge.source_id)
            target = self._nodes.get(edge.target_id)
            if source is None or target is None:
                continue
            edge_item = GraphEdgeItem(edge, source, target, border=palette.border_strong)
            self._scene.addItem(edge_item)
            self._edges.append(edge_item)
            self._adjacency[edge.source_id].add(edge.target_id)
            self._adjacency[edge.target_id].add(edge.source_id)

        render_ms = (time.perf_counter() - render_start) * 1000
        self.fit()
        self.metrics.emit(
            {
                "layout_ms": round(layout_ms, 2),
                "render_ms": round(render_ms, 2),
                "node_count": float(len(view.nodes)),
                "edge_count": float(len(view.edges)),
            }
        )

    def clear(self) -> None:
        """Remove all items from the canvas."""
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()
        self._adjacency.clear()

    # --- viewport controls ----------------------------------------------

    def fit(self) -> None:
        """Fit the whole graph into the viewport."""
        if not self._nodes:
            return
        rect = self._scene.itemsBoundingRect()
        rect = rect.adjusted(-_FIT_MARGIN, -_FIT_MARGIN, _FIT_MARGIN, _FIT_MARGIN)
        self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
        self._scale = self.transform().m11()

    def zoom_in(self) -> None:
        """Zoom in by one step."""
        self._apply_zoom(_ZOOM_STEP)

    def zoom_out(self) -> None:
        """Zoom out by one step."""
        self._apply_zoom(1 / _ZOOM_STEP)

    def focus_node(self, node_id: str) -> None:
        """Centre the viewport on a node and select it."""
        item = self._nodes.get(node_id)
        if item is None:
            return
        self._scene.clearSelection()
        item.setSelected(True)
        self.centerOn(item)

    def _apply_zoom(self, factor: float) -> None:
        target = self._scale * factor
        if target < _MIN_SCALE or target > _MAX_SCALE:
            return
        self._scale = target
        self.scale(factor, factor)

    # --- viewport capture / restore (session prep) ----------------------

    def viewport_scale(self) -> float:
        """The current zoom scale (session capture helper)."""
        return self._scale

    def viewport_center(self) -> tuple[float, float]:
        """The scene coordinate at the viewport centre (session capture helper)."""
        center = self.mapToScene(self.viewport().rect().center())
        return center.x(), center.y()

    def apply_viewport(self, scale: float, center_x: float, center_y: float) -> None:
        """Restore a captured viewport (zoom + centre)."""
        clamped = max(_MIN_SCALE, min(_MAX_SCALE, scale))
        self.resetTransform()
        self.scale(clamped, clamped)
        self._scale = clamped
        self.centerOn(center_x, center_y)

    # --- highlighting & filtering ---------------------------------------

    def highlight_nodes(self, node_ids: Iterable[str]) -> None:
        """Highlight a set of nodes (e.g. search matches)."""
        wanted = set(node_ids)
        for node_id, item in self._nodes.items():
            item.set_highlighted(node_id in wanted)

    def clear_highlight(self) -> None:
        """Clear all node/edge highlighting."""
        for item in self._nodes.values():
            item.set_highlighted(False)
        for edge in self._edges:
            edge.set_highlighted(False)

    def set_visible(self, node_ids: Iterable[str], edge_ids: Iterable[str]) -> None:
        """Dim nodes/edges not in the given sets (filter/timeline focus)."""
        visible_nodes = set(node_ids)
        visible_edges = set(edge_ids)
        for node_id, item in self._nodes.items():
            item.set_dimmed(node_id not in visible_nodes)
        for edge in self._edges:
            edge.set_dimmed(edge.edge_id not in visible_edges)

    def reset_visibility(self) -> None:
        """Restore full visibility."""
        for item in self._nodes.values():
            item.set_dimmed(False)
        for edge in self._edges:
            edge.set_dimmed(False)

    def _reposition_edges(self) -> None:
        for edge in self._edges:
            edge.reposition()

    def _on_hover(self, node_id: str, entered: bool) -> None:
        if not entered:
            self.clear_highlight()
            return
        neighbours = self._adjacency.get(node_id, set())
        for other_id, item in self._nodes.items():
            item.set_highlighted(other_id == node_id or other_id in neighbours)
        for edge in self._edges:
            source, target = edge.endpoints()
            edge.set_highlighted(node_id in (source, target))

    # --- mouse interaction ----------------------------------------------

    def wheelEvent(self, event: QWheelEvent) -> None:  # noqa: N802 - Qt override
        """Zoom with the mouse wheel."""
        self._apply_zoom(_ZOOM_STEP if event.angleDelta().y() > 0 else 1 / _ZOOM_STEP)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        """Handle edge selection and start background panning."""
        item = self.itemAt(event.position().toPoint())
        if isinstance(item, GraphEdgeItem):
            self.edge_clicked.emit(item.edge_id)
            return
        if item is None:
            self._panning = True
            self._pan_start = (event.position().x(), event.position().y())
            self._scene.clearSelection()
            self.background_clicked.emit()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        """Pan the viewport while dragging the background."""
        if self._panning:
            dx = event.position().x() - self._pan_start[0]
            dy = event.position().y() - self._pan_start[1]
            self._pan_start = (event.position().x(), event.position().y())
            h = self.horizontalScrollBar()
            v = self.verticalScrollBar()
            h.setValue(h.value() - int(dx))
            v.setValue(v.value() - int(dy))
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        """End background panning."""
        if self._panning:
            self._panning = False
            self.setCursor(Qt.CursorShape.ArrowCursor)
            return
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        """Request expansion of a double-clicked node."""
        item = self.itemAt(event.position().toPoint())
        if isinstance(item, GraphNodeItem):
            self.node_expand_requested.emit(item.node_id)
            return
        parent = item.parentItem() if item is not None else None
        if isinstance(parent, GraphNodeItem):
            self.node_expand_requested.emit(parent.node_id)
            return
        super().mouseDoubleClickEvent(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802 - Qt override
        """Keyboard navigation: +/- zoom, F fit, arrow keys pan."""
        key = event.key()
        if key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
            self.zoom_in()
        elif key in (Qt.Key.Key_Minus, Qt.Key.Key_Underscore):
            self.zoom_out()
        elif key in (Qt.Key.Key_F, Qt.Key.Key_Home):
            self.fit()
        elif key in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Up, Qt.Key.Key_Down):
            self._pan_by_key(key)
        else:
            super().keyPressEvent(event)

    def _pan_by_key(self, key: int) -> None:
        step = _KEY_PAN_STEP
        h = self.horizontalScrollBar()
        v = self.verticalScrollBar()
        if key == Qt.Key.Key_Left:
            h.setValue(h.value() - step)
        elif key == Qt.Key.Key_Right:
            h.setValue(h.value() + step)
        elif key == Qt.Key.Key_Up:
            v.setValue(v.value() - step)
        elif key == Qt.Key.Key_Down:
            v.setValue(v.value() + step)

    def viewport_rect(self) -> QRectF:
        """Return the current scene rect (test/inspection helper)."""
        return self._scene.itemsBoundingRect()

    @property
    def node_items(self) -> dict[str, GraphNodeItem]:
        """The rendered node items, keyed by id (inspection helper)."""
        return self._nodes

    @property
    def edge_items(self) -> list[GraphEdgeItem]:
        """The rendered edge items (inspection helper)."""
        return self._edges

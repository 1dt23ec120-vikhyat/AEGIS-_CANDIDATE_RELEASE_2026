"""Graph scene items.

The :class:`QGraphicsItem` primitives rendered by the canvas: a coloured node
with a type glyph and label, and a relationship edge that tracks its endpoints.
Interaction (selection, drag, hover) is surfaced to the canvas through small
callbacks so the canvas owns coordination while items stay simple.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QPointF
from PySide6.QtGui import QBrush, QColor, QFont, QPen
from PySide6.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsSimpleTextItem,
)

from core.domain.graph_view import GraphEdgeView, GraphNodeView
from ui.components.graph.identity import NodeIdentity

NODE_RADIUS = 20.0
_LABEL_MAX = 26


class GraphNodeItem(QGraphicsEllipseItem):
    """A draggable, selectable graph node with a glyph and label."""

    def __init__(
        self,
        node: GraphNodeView,
        identity: NodeIdentity,
        *,
        on_moved: Callable[[], None],
        on_hover: Callable[[str, bool], None],
        on_clicked: Callable[[str], None],
    ) -> None:
        """Build the node item."""
        super().__init__(-NODE_RADIUS, -NODE_RADIUS, NODE_RADIUS * 2, NODE_RADIUS * 2)
        self.node_id = node.node_id
        self.node = node
        self._identity = identity
        self._on_moved = on_moved
        self._on_hover = on_hover
        self._on_clicked = on_clicked
        self._highlighted = False

        self.setBrush(QBrush(QColor(identity.fill)))
        self.setPen(self._default_pen())
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(2)
        self.setToolTip(f"{identity.label}: {node.label}")

        glyph = QGraphicsSimpleTextItem(identity.glyph, self)
        glyph.setBrush(QBrush(QColor(identity.text)))
        glyph_font = QFont()
        glyph_font.setBold(True)
        glyph_font.setPointSizeF(10.0)
        glyph.setFont(glyph_font)
        grect = glyph.boundingRect()
        glyph.setPos(-grect.width() / 2, -grect.height() / 2)

        caption = _truncate(node.label)
        text = QGraphicsSimpleTextItem(caption, self)
        text.setBrush(QBrush(QColor(identity.border)))
        label_font = QFont()
        label_font.setPointSizeF(8.0)
        text.setFont(label_font)
        trect = text.boundingRect()
        text.setPos(-trect.width() / 2, NODE_RADIUS + 3)

    def _default_pen(self) -> QPen:
        pen = QPen(QColor(self._identity.border))
        pen.setWidthF(1.5)
        return pen

    def set_highlighted(self, highlighted: bool) -> None:
        """Toggle a highlight ring on the node."""
        self._highlighted = highlighted
        if highlighted:
            pen = QPen(QColor("#FFFFFF"))
            pen.setWidthF(3.0)
            self.setPen(pen)
        else:
            self.setPen(self._default_pen())

    def set_dimmed(self, dimmed: bool) -> None:
        """Fade the node when it is filtered out of focus."""
        self.setOpacity(0.25 if dimmed else 1.0)

    def itemChange(  # noqa: N802 - Qt override
        self,
        change: QGraphicsItem.GraphicsItemChange,
        value: object,
    ) -> object:
        """Notify the canvas when the node moves so edges follow."""
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self._on_moved()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event: object) -> None:  # noqa: N802 - Qt override
        """Report hover-in for relationship highlighting."""
        self._on_hover(self.node_id, True)
        super().hoverEnterEvent(event)  # type: ignore[arg-type]

    def hoverLeaveEvent(self, event: object) -> None:  # noqa: N802 - Qt override
        """Report hover-out."""
        self._on_hover(self.node_id, False)
        super().hoverLeaveEvent(event)  # type: ignore[arg-type]

    def mousePressEvent(self, event: object) -> None:  # noqa: N802 - Qt override
        """Report selection to the canvas."""
        self._on_clicked(self.node_id)
        super().mousePressEvent(event)  # type: ignore[arg-type]


class GraphEdgeItem(QGraphicsLineItem):
    """A relationship edge that tracks its endpoint nodes."""

    def __init__(
        self,
        edge: GraphEdgeView,
        source: GraphNodeItem,
        target: GraphNodeItem,
        *,
        border: str,
    ) -> None:
        """Build the edge item."""
        super().__init__()
        self.edge_id = edge.edge_id
        self.edge = edge
        self._source = source
        self._target = target
        self._border = border
        self.setZValue(1)
        self.setPen(self._default_pen())
        self.setToolTip(f"{edge.relationship} ({edge.confidence:.0%})")
        self.reposition()

    def _default_pen(self) -> QPen:
        pen = QPen(QColor(self._border))
        pen.setWidthF(1.2)
        return pen

    def reposition(self) -> None:
        """Set the line to run between the current node centres."""
        p1: QPointF = self._source.pos()
        p2: QPointF = self._target.pos()
        self.setLine(p1.x(), p1.y(), p2.x(), p2.y())

    def endpoints(self) -> tuple[str, str]:
        """Return the (source_id, target_id) this edge connects."""
        return self._source.node_id, self._target.node_id

    def set_highlighted(self, highlighted: bool) -> None:
        """Toggle emphasis on the edge."""
        if highlighted:
            pen = QPen(QColor("#4C8DFF"))
            pen.setWidthF(2.6)
            self.setPen(pen)
        else:
            self.setPen(self._default_pen())

    def set_dimmed(self, dimmed: bool) -> None:
        """Fade the edge when filtered out of focus."""
        self.setOpacity(0.15 if dimmed else 1.0)


def _truncate(text: str) -> str:
    return text if len(text) <= _LABEL_MAX else f"{text[: _LABEL_MAX - 1]}\u2026"


__all__ = ["NODE_RADIUS", "GraphEdgeItem", "GraphNodeItem"]

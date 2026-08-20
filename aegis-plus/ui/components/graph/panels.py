"""Graph explorer panels.

The analyst side panels around the canvas: search (with history), filters
(node type / relationship / confidence), timeline, node details, relationship
details, an analytics summary (with observability metrics), and a type legend.
Each is a self-contained widget that emits intents and renders view DTOs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from core.domain.graph_view import (
    GraphAnalyticsSummary,
    GraphEdgeView,
    GraphNodeView,
    GraphSearchResult,
    GraphSnapshotView,
)
from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.graph.identity import NODE_TYPE_ORDER, node_identity, type_label
from ui.components.inputs import SearchBar
from ui.components.section import Section
from ui.components.tables import DataTable
from ui.components.text import label
from ui.theme import ThemeManager

_DASH = "\u2014"
_HISTORY_LIMIT = 8


@dataclass(frozen=True, slots=True)
class FilterCriteria:
    """Client-side graph filter selection. Empty sets mean 'all'."""

    node_types: frozenset[str] = field(default_factory=frozenset)
    relationships: frozenset[str] = field(default_factory=frozenset)
    min_confidence: float = 0.0

    def allows_node(self, node_type: str) -> bool:
        """Whether a node type passes the filter."""
        return not self.node_types or node_type in self.node_types

    def allows_edge(self, relationship: str, confidence: float) -> bool:
        """Whether an edge passes the relationship + confidence filter."""
        if self.relationships and relationship not in self.relationships:
            return False
        return confidence >= self.min_confidence


class GraphSearchPanel(Section):
    """Search box with results and recent-query history."""

    search_submitted = Signal(str)
    result_activated = Signal(str)

    def __init__(self, *, parent: QWidget | None = None) -> None:
        """Build the search panel."""
        super().__init__("Search", parent=parent)
        self._input = SearchBar(placeholder="Search nodes, hashes, URLs, IOCs\u2026")
        self._input.returnPressed.connect(self._submit)
        self._results = QListWidget()
        self._results.itemActivated.connect(self._activate)
        self._results.itemClicked.connect(self._activate)
        self._results.setMaximumHeight(180)
        self._history = QListWidget()
        self._history.itemClicked.connect(self._replay)
        self._history.setMaximumHeight(120)
        self._history_terms: list[str] = []

        self.add_body(self._input)
        self.add_body(label("Results", role="muted"))
        self.add_body(self._results)
        self.add_body(label("Recent", role="muted"))
        self.add_body(self._history)

    def _submit(self) -> None:
        term = self._input.text().strip()
        if term:
            self._remember(term)
            self.search_submitted.emit(term)

    def _activate(self, item: QListWidgetItem) -> None:
        node_id = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(node_id, str) and node_id:
            self.result_activated.emit(node_id)

    def _replay(self, item: QListWidgetItem) -> None:
        term = item.text()
        self._input.setText(term)
        self.search_submitted.emit(term)

    def _remember(self, term: str) -> None:
        if term in self._history_terms:
            self._history_terms.remove(term)
        self._history_terms.insert(0, term)
        del self._history_terms[_HISTORY_LIMIT:]
        self._history.clear()
        self._history.addItems(self._history_terms)

    def set_results(self, result: GraphSearchResult) -> None:
        """Populate the results list from a search result."""
        self._results.clear()
        for match in result.matches:
            item = QListWidgetItem(f"{type_label(match.node_type)}  \u00b7  {match.label}")
            item.setData(Qt.ItemDataRole.UserRole, match.node_id)
            self._results.addItem(item)
        if not result.matches:
            self._results.addItem(QListWidgetItem("No matches"))


class GraphFiltersPanel(Section):
    """Filter the visible graph by node type, relationship, and confidence."""

    filters_changed = Signal(object)  # FilterCriteria

    def __init__(self, *, parent: QWidget | None = None) -> None:
        """Build the filters panel."""
        super().__init__("Filters", parent=parent)
        self._node_boxes: dict[str, QCheckBox] = {}
        self._rel_boxes: dict[str, QCheckBox] = {}

        self._node_container = QWidget()
        self._node_grid = QGridLayout(self._node_container)
        self._node_grid.setContentsMargins(0, 0, 0, 0)
        self._rel_container = QWidget()
        self._rel_layout = QVBoxLayout(self._rel_container)
        self._rel_layout.setContentsMargins(0, 0, 0, 0)

        self._confidence = QSlider(Qt.Orientation.Horizontal)
        self._confidence.setRange(0, 100)
        self._confidence.setValue(0)
        self._confidence.valueChanged.connect(lambda _v: self._emit())
        self._confidence_label = label("Min confidence: 0%", role="muted")

        reset = Button("Reset filters", variant="ghost")
        reset.clicked.connect(self._reset)

        self.add_body(label("Node types", role="muted"))
        self.add_body(self._node_container)
        self.add_body(label("Relationships", role="muted"))
        self.add_body(self._rel_container)
        self.add_body(self._confidence_label)
        self.add_body(self._confidence)
        self.add_body(reset)

    def set_available(self, node_types: list[str], relationships: list[str]) -> None:
        """Rebuild the checkbox sets from what is present in the graph."""
        self._rebuild(self._node_grid, self._node_boxes, node_types, grid=True)
        self._rebuild(self._rel_layout, self._rel_boxes, relationships, grid=False)

    def _rebuild(
        self,
        layout: QGridLayout | QVBoxLayout,
        registry: dict[str, QCheckBox],
        values: list[str],
        *,
        grid: bool,
    ) -> None:
        for box in registry.values():
            box.setParent(None)
        registry.clear()
        for index, value in enumerate(values):
            box = QCheckBox(type_label(value) if grid else value.replace("_", " ").title())
            box.setChecked(True)
            box.stateChanged.connect(lambda _s: self._emit())
            registry[value] = box
            if isinstance(layout, QGridLayout):
                layout.addWidget(box, index // 2, index % 2)
            else:
                layout.addWidget(box)

    def _selected(self, registry: dict[str, QCheckBox], universe: int) -> frozenset[str]:
        chosen = {value for value, box in registry.items() if box.isChecked()}
        # All selected -> empty set (means 'all', avoids over-filtering).
        return frozenset() if len(chosen) == universe else frozenset(chosen)

    def _emit(self) -> None:
        conf = self._confidence.value() / 100.0
        self._confidence_label.setText(f"Min confidence: {self._confidence.value()}%")
        self.filters_changed.emit(
            FilterCriteria(
                node_types=self._selected(self._node_boxes, len(self._node_boxes)),
                relationships=self._selected(self._rel_boxes, len(self._rel_boxes)),
                min_confidence=conf,
            )
        )

    def _reset(self) -> None:
        for box in (*self._node_boxes.values(), *self._rel_boxes.values()):
            box.setChecked(True)
        self._confidence.setValue(0)
        self._emit()


class GraphTimelinePanel(Section):
    """Explore how relationships accrued over time using edge timestamps."""

    cutoff_changed = Signal(str)  # "" means show all

    def __init__(self, *, parent: QWidget | None = None) -> None:
        """Build the timeline panel."""
        super().__init__("Timeline", parent=parent)
        self._timestamps: list[str] = []
        self._slider = QSlider(Qt.Orientation.Horizontal)
        self._slider.setRange(0, 0)
        self._slider.valueChanged.connect(self._on_slide)
        self._label = label("No temporal data", role="muted")
        show_all = Button("Show all", variant="ghost")
        show_all.clicked.connect(self._show_all)
        self.add_body(self._label)
        self.add_body(self._slider)
        self.add_body(show_all)

    def set_timestamps(self, timestamps: list[str]) -> None:
        """Provide the sorted unique timestamps present in the graph."""
        self._timestamps = sorted(t for t in timestamps if t)
        count = len(self._timestamps)
        self._slider.setRange(0, max(count - 1, 0))
        if count:
            self._slider.setValue(count - 1)
            self._label.setText(f"Up to {self._timestamps[-1]}")
        else:
            self._label.setText("No temporal data")

    def _on_slide(self, index: int) -> None:
        if not self._timestamps:
            return
        index = min(index, len(self._timestamps) - 1)
        cutoff = self._timestamps[index]
        self._label.setText(f"Up to {cutoff}")
        is_last = index == len(self._timestamps) - 1
        self.cutoff_changed.emit("" if is_last else cutoff)

    def _show_all(self) -> None:
        if self._timestamps:
            self._slider.setValue(len(self._timestamps) - 1)
        self.cutoff_changed.emit("")


class NodeDetailsPanel(Section):
    """Details and pivot actions for the selected node."""

    expand_requested = Signal(str)
    focus_requested = Signal(str)
    open_investigation_requested = Signal(str)

    def __init__(self, *, parent: QWidget | None = None) -> None:
        """Build the node details panel."""
        super().__init__("Node Details", parent=parent)
        self._node_id = ""
        self._summary = label("Select a node to inspect it.", role="muted")
        self._badges = QWidget()
        self._badge_row = QHBoxLayout(self._badges)
        self._badge_row.setContentsMargins(0, 0, 0, 0)
        self._table = DataTable(["Field", "Value"])
        self._expand = Button("Expand", variant="secondary")
        self._expand.clicked.connect(self._emit_expand)
        self._focus = Button("Focus", variant="secondary")
        self._focus.clicked.connect(self._emit_focus)
        self._investigate = Button("Open Investigation", variant="ghost")
        self._investigate.clicked.connect(self._emit_investigate)
        actions = QHBoxLayout()
        actions.addWidget(self._expand)
        actions.addWidget(self._focus)
        actions.addWidget(self._investigate)
        self.add_body(self._summary)
        self.add_body(self._badges)
        self.add_body(self._table)
        self._actions_host = QWidget()
        self._actions_host.setLayout(actions)
        self.add_body(self._actions_host)
        self._set_actions_enabled(False)

    def _emit_expand(self) -> None:
        if self._node_id:
            self.expand_requested.emit(self._node_id)

    def _emit_focus(self) -> None:
        if self._node_id:
            self.focus_requested.emit(self._node_id)

    def _emit_investigate(self) -> None:
        if self._node_id:
            self.open_investigation_requested.emit(self._node_id)

    def _set_actions_enabled(self, enabled: bool) -> None:
        for button in (self._expand, self._focus, self._investigate):
            button.setEnabled(enabled)

    def set_node(self, node: GraphNodeView | None) -> None:
        """Render a node's details, or a placeholder when cleared."""
        while self._badge_row.count():
            item = self._badge_row.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.setParent(None)
        if node is None:
            self._node_id = ""
            self._summary.setText("Select a node to inspect it.")
            self._table.set_rows([])
            self._set_actions_enabled(False)
            return
        self._node_id = node.node_id
        self._summary.setText(node.label)
        self._badge_row.addWidget(Badge(type_label(node.node_type), tone="info"))
        if node.risk_percent:
            self._badge_row.addWidget(Badge(f"{node.risk_percent}% risk", tone=node.tone))
        self._badge_row.addStretch(1)
        rows = [
            ["Identifier", node.node_id],
            ["Type", type_label(node.node_type)],
            ["Connections", str(node.degree)],
        ]
        rows.extend([key, value] for key, value in sorted(node.metadata.items()))
        self._table.set_rows(rows)
        self._set_actions_enabled(True)


class RelationshipDetailsPanel(Section):
    """Details for the selected relationship."""

    def __init__(self, *, parent: QWidget | None = None) -> None:
        """Build the relationship details panel."""
        super().__init__("Relationship Details", parent=parent)
        self._summary = label("Select a relationship to inspect it.", role="muted")
        self._table = DataTable(["Field", "Value"])
        self.add_body(self._summary)
        self.add_body(self._table)

    def set_edge(self, edge: GraphEdgeView | None) -> None:
        """Render an edge's details, or a placeholder when cleared."""
        if edge is None:
            self._summary.setText("Select a relationship to inspect it.")
            self._table.set_rows([])
            return
        self._summary.setText(edge.relationship.replace("_", " ").title())
        self._table.set_rows(
            [
                ["From", edge.source_id],
                ["To", edge.target_id],
                ["Type", edge.relationship],
                ["Confidence", f"{edge.confidence:.0%}"],
                ["Provenance", edge.provenance or _DASH],
                ["Observed", edge.timestamp or _DASH],
            ]
        )


class AnalyticsSummaryPanel(Section):
    """Graph analytics and observability metrics."""

    def __init__(self, *, parent: QWidget | None = None) -> None:
        """Build the analytics panel."""
        super().__init__("Analytics", parent=parent)
        self._counts = label("", role="body")
        self._structure = label("", role="muted")
        self._connected = DataTable(["Entity", "Connections"])
        self._entities = DataTable(["Entity type", "Count"])
        self._relationships = DataTable(["Relationship", "Count"])
        self._metrics = DataTable(["Metric", "Value"])
        self.add_body(self._counts)
        self.add_body(self._structure)
        self.add_body(label("Most connected", role="muted"))
        self.add_body(self._connected)
        self.add_body(label("Entity distribution", role="muted"))
        self.add_body(self._entities)
        self.add_body(label("Relationship distribution", role="muted"))
        self.add_body(self._relationships)
        self.add_body(label("Observability", role="muted"))
        self.add_body(self._metrics)

    def set_snapshot(self, snapshot: GraphSnapshotView) -> None:
        """Render top-level graph counts."""
        self._counts.setText(
            f"{snapshot.node_count} nodes  \u00b7  {snapshot.edge_count} relationships"
        )

    def set_analytics(self, analytics: GraphAnalyticsSummary) -> None:
        """Render analytics: distributions, connectivity, and structure."""
        self._counts.setText(
            f"{analytics.node_count} nodes  \u00b7  {analytics.edge_count} relationships"
            f"  \u00b7  {analytics.ioc_count} IOCs"
        )
        self._structure.setText(
            f"{analytics.component_count} components  \u00b7  "
            f"largest {analytics.largest_component_size}  \u00b7  "
            f"density {analytics.density * 100:.1f}%  \u00b7  "
            f"blast radius {analytics.reachable_from_top}"
        )
        self._connected.set_rows(
            [[entity.node.label, str(entity.degree)] for entity in analytics.most_connected]
        )
        self._entities.set_rows(
            [[type_label(name), str(count)] for name, count in analytics.node_type_counts]
        )
        self._relationships.set_rows(
            [
                [name.replace("_", " ").title(), str(count)]
                for name, count in analytics.relationship_type_counts
            ]
        )

    def set_metrics(self, metrics: dict[str, float]) -> None:
        """Render observability metrics from the last interactions."""
        rows: list[list[str]] = []
        for key, formatter in _METRIC_ROWS:
            if key in metrics:
                rows.append([_METRIC_LABELS[key], formatter(metrics[key])])
        self._metrics.set_rows(rows)


def _ms(value: float) -> str:
    return f"{value:.1f} ms"


def _count(value: float) -> str:
    return str(int(value))


_METRIC_LABELS: dict[str, str] = {
    "layout_ms": "Layout duration",
    "render_ms": "Render duration",
    "query_ms": "Backend query",
    "expand_ms": "Expansion latency",
    "search_ms": "Search latency",
    "timeline_ms": "Timeline filter",
    "node_count": "Nodes",
    "edge_count": "Relationships",
    "visible_node_count": "Visible nodes",
    "hidden_node_count": "Hidden nodes",
    "expansion_count": "Expansions",
    "expansion_depth": "Expand depth",
}
_METRIC_ROWS: tuple[tuple[str, Callable[[float], str]], ...] = (
    ("query_ms", _ms),
    ("layout_ms", _ms),
    ("render_ms", _ms),
    ("expand_ms", _ms),
    ("search_ms", _ms),
    ("timeline_ms", _ms),
    ("node_count", _count),
    ("edge_count", _count),
    ("visible_node_count", _count),
    ("hidden_node_count", _count),
    ("expansion_count", _count),
    ("expansion_depth", _count),
)


class GraphLegend(QWidget):
    """A compact legend mapping node types to their colours."""

    def __init__(self, theme_manager: ThemeManager, *, parent: QWidget | None = None) -> None:
        """Build the legend."""
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        palette = theme_manager.theme.palette
        for node_type in NODE_TYPE_ORDER:
            identity = node_identity(node_type, palette)
            swatch = QLabel("\u25cf")
            swatch.setStyleSheet(f"color: {identity.fill}; font-size: 13px;")
            entry: QLabel = label(identity.label, role="caption")
            row.addWidget(swatch)
            row.addWidget(entry)
        row.addStretch(1)


__all__ = [
    "AnalyticsSummaryPanel",
    "FilterCriteria",
    "GraphFiltersPanel",
    "GraphLegend",
    "GraphSearchPanel",
    "GraphTimelinePanel",
    "NodeDetailsPanel",
    "RelationshipDetailsPanel",
]

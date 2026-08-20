"""Intelligence Graph Explorer page.

The analyst-facing workspace: an interactive graph canvas with a toolbar and a
column of analyst panels (search, filters, timeline, node/relationship details,
analytics). It is a thin view over :class:`GraphExplorerViewModel` — all state and
backend access live in the view-model; this page only wires widgets to signals.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

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
from ui.components.buttons import Button
from ui.components.graph import (
    AnalyticsSummaryPanel,
    FilterCriteria,
    GraphCanvas,
    GraphFiltersPanel,
    GraphLegend,
    GraphSearchPanel,
    GraphTimelinePanel,
    GraphToolbar,
    NodeDetailsPanel,
    RelationshipDetailsPanel,
)
from ui.components.text import label
from ui.context import UIContext
from ui.navigation import Route
from ui.pages.base_page import BasePage
from ui.viewmodels.explorer_session import ExplorerSessionState, ViewportState
from ui.viewmodels.graph_explorer import GraphExplorerViewModel, RunnerFactory

_PANEL_WIDTH = 380


class GraphExplorerPage(BasePage):
    """Interactive Intelligence Graph Explorer."""

    def __init__(
        self,
        context: UIContext,
        *,
        runner_factory: RunnerFactory = AsyncRunner,
        parent: QWidget | None = None,
    ) -> None:
        """Build the Graph Explorer page.

        Args:
            context: Shared UI dependencies (theme, backend client, navigation).
            runner_factory: Worker factory for the view-model's backend calls;
                defaults to the threaded runner. Tests may inject a synchronous
                runner.
            parent: Optional Qt parent.
        """
        super().__init__(
            "Intelligence Graph Explorer",
            "Explore relationships, pivot across entities, and trace attack paths",
            parent=parent,
        )
        self._context = context
        self._client: BackendClient = context.backend_client
        self._vm = GraphExplorerViewModel(self._client, runner_factory=runner_factory)
        self._depth = 1
        self._metrics: dict[str, float] = {}
        self._origin: Route | None = None

        self._back = Button("\u2190 Back to investigation", variant="ghost")
        self._back.clicked.connect(self._go_back)
        self._overlay_btn = Button("Analytics Overlay", variant="ghost")
        self._overlay_btn.setCheckable(True)
        self._overlay_btn.setToolTip(
            "Highlight critical nodes and attack paths from the analytics engine"
        )
        self._overlay_btn.clicked.connect(self._toggle_overlay)
        self._overlay_on = False
        self._back.hide()
        self.header.add_action(self._back)

        self._selected_node: str = ""
        self._copilot_action = Button("Ask Copilot", variant="ghost")
        self._copilot_action.clicked.connect(self._ask_copilot)
        self._copilot_action.setEnabled(False)
        self.header.add_action(self._copilot_action)

        self._toolbar = GraphToolbar()
        self._canvas = GraphCanvas(context.theme_manager)
        self._hint = label(
            "Search for an artifact, or open the Explorer from an investigation, to begin.",
            role="muted",
        )
        self._status: QLabel = label("", role="muted")

        self._search = GraphSearchPanel()
        self._filters = GraphFiltersPanel()
        self._timeline = GraphTimelinePanel()
        self._node_details = NodeDetailsPanel()
        self._rel_details = RelationshipDetailsPanel()
        self._analytics = AnalyticsSummaryPanel()

        self._build_layout(context)
        self._wire()
        self._vm.load_overview()

    # --- layout ----------------------------------------------------------

    def _build_layout(self, context: UIContext) -> None:
        self.add(self._toolbar)

        canvas_side = QWidget()
        canvas_col = QVBoxLayout(canvas_side)
        canvas_col.setContentsMargins(0, 0, 0, 0)
        canvas_col.setSpacing(8)
        overlay_row = QHBoxLayout()
        overlay_row.addWidget(self._overlay_btn)
        overlay_row.addStretch(1)
        canvas_col.addLayout(overlay_row)
        canvas_col.addWidget(self._hint)
        canvas_col.addWidget(self._canvas, 1)
        canvas_col.addWidget(GraphLegend(context.theme_manager))
        canvas_col.addWidget(self._status)

        panel_host = QWidget()
        panel_col = QVBoxLayout(panel_host)
        panel_col.setContentsMargins(0, 0, 0, 0)
        panel_col.setSpacing(14)
        for panel in (
            self._search,
            self._filters,
            self._timeline,
            self._node_details,
            self._rel_details,
            self._analytics,
        ):
            panel_col.addWidget(panel)
        panel_col.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(panel_host)
        scroll.setFixedWidth(_PANEL_WIDTH)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(canvas_side)
        splitter.addWidget(scroll)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
        self.add(splitter)

    # --- wiring ----------------------------------------------------------

    def _wire(self) -> None:
        self._toolbar.fit_requested.connect(self._canvas.fit)
        self._toolbar.zoom_in_requested.connect(self._canvas.zoom_in)
        self._toolbar.zoom_out_requested.connect(self._canvas.zoom_out)
        self._toolbar.reload_requested.connect(self._reload)
        self._toolbar.depth_changed.connect(self._set_depth)

        self._canvas.node_clicked.connect(self._vm.select_node)
        self._canvas.edge_clicked.connect(self._vm.select_edge)
        self._canvas.node_expand_requested.connect(self._on_expand)
        self._canvas.background_clicked.connect(self._vm.clear_selection)
        self._canvas.metrics.connect(self._on_canvas_metrics)

        self._search.search_submitted.connect(self._vm.search)
        self._search.result_activated.connect(self._vm.focus)
        self._filters.filters_changed.connect(self._on_filters)
        self._timeline.cutoff_changed.connect(self._vm.set_cutoff)

        self._node_details.expand_requested.connect(self._on_expand)
        self._node_details.focus_requested.connect(self._vm.focus)
        self._node_details.open_investigation_requested.connect(self._open_investigation)

        self._vm.snapshot_ready.connect(self._on_snapshot)
        self._vm.overlay_ready.connect(self._on_overlay)
        self._vm.analytics_ready.connect(self._on_analytics)
        self._vm.graph_ready.connect(self._on_graph)
        self._vm.focus_requested.connect(self._canvas.focus_node)
        self._vm.visibility_changed.connect(self._canvas.set_visible)
        self._vm.node_details.connect(self._on_node_details)
        self._vm.edge_details.connect(self._on_edge_details)
        self._vm.search_ready.connect(self._on_search_results)
        self._vm.busy_changed.connect(self._on_busy)
        self._vm.error.connect(self._on_error)
        self._vm.expand_metric.connect(self._on_expand_metric)
        self._vm.metrics_ready.connect(self._on_vm_metrics)

    # --- navigation integration -----------------------------------------

    def on_navigated(self, payload: object) -> None:
        """Focus an artifact when opened from an investigation workspace."""
        if not isinstance(payload, dict):
            return
        origin = payload.get("origin")
        self._origin = origin if isinstance(origin, Route) else None
        self._back.setVisible(self._origin is not None)
        node_id = payload.get("focus")
        if isinstance(node_id, str) and node_id:
            self._vm.load_neighbors(node_id, depth=self._depth)

    def _go_back(self) -> None:
        if self._origin is not None:
            self._context.go_to(self._origin)

    # --- analytics overlay (M11 Phase E) --------------------------------

    def _toggle_overlay(self) -> None:
        self._overlay_on = self._overlay_btn.isChecked()
        if self._overlay_on:
            self._status.setText("Loading analytics overlay\u2026")
            self._vm.load_overlay(top=10)
        else:
            self._canvas.highlight_nodes([])
            self._status.setText("Analytics overlay cleared")

    def _on_overlay(self, overlay: object) -> None:
        if not isinstance(overlay, GraphOverlay) or not self._overlay_on:
            return
        emphasis = set(overlay.critical_ids) | set(overlay.attack_path_ids)
        self._canvas.highlight_nodes(emphasis)
        self._status.setText(
            f"Overlay: {len(overlay.critical_ids)} critical node(s), "
            f"{len(overlay.attack_path_ids)} on attack paths"
        )

    # --- session capture / restore (in-memory only) ---------------------

    def session_state(self) -> ExplorerSessionState:
        """Capture the current Explorer session (presentation-only, in-memory)."""
        center_x, center_y = self._canvas.viewport_center()
        return self._vm.session_state(
            ViewportState(
                scale=self._canvas.viewport_scale(),
                center_x=center_x,
                center_y=center_y,
            )
        )

    def restore_session(self, state: ExplorerSessionState) -> None:
        """Restore a previously captured session (no persistence)."""
        self._vm.restore_session(state)
        viewport = state.viewport
        self._canvas.apply_viewport(viewport.scale, viewport.center_x, viewport.center_y)

    def _open_investigation(self, node_id: str) -> None:
        node = next((n for n in self._vm.current_view.nodes if n.node_id == node_id), None)
        if node is None:
            return
        route = (
            Route.INCIDENTS if node.node_type in {"incident", "campaign"} else Route.FILE_SCANNER
        )
        self._context.go_to(route)

    # --- slots -----------------------------------------------------------

    def _set_depth(self, depth: int) -> None:
        self._depth = depth

    def _reload(self) -> None:
        self._vm.load_overview()

    def _on_expand(self, node_id: str) -> None:
        self._vm.expand(node_id, depth=self._depth)

    def _on_filters(self, criteria: object) -> None:
        if isinstance(criteria, FilterCriteria):
            self._vm.set_filters(criteria)

    def _on_snapshot(self, snapshot: object) -> None:
        if isinstance(snapshot, GraphSnapshotView):
            self._analytics.set_snapshot(snapshot)

    def _on_analytics(self, analytics: object) -> None:
        if isinstance(analytics, GraphAnalyticsSummary):
            self._analytics.set_analytics(analytics)

    def _on_graph(self, view: object) -> None:
        if not isinstance(view, GraphView):
            return
        self._hint.setVisible(not view.nodes)
        self._canvas.set_graph(view)
        self._filters.set_available(
            self._vm.available_node_types(), self._vm.available_relationships()
        )
        self._timeline.set_timestamps(self._vm.timestamps())
        self._node_details.set_node(None)
        self._rel_details.set_edge(None)
        if view.truncated:
            self._status.setText("View truncated for performance; refine with search or filters.")
        else:
            self._status.setText(f"{view.node_count} nodes \u00b7 {view.edge_count} relationships")

    def _on_node_details(self, node: object) -> None:
        if node is None or isinstance(node, GraphNodeView):
            self._node_details.set_node(node)
            if isinstance(node, GraphNodeView):
                self._selected_node = node.node_id
                self._copilot_action.setEnabled(bool(node.node_id))
            else:
                self._selected_node = ""
                self._copilot_action.setEnabled(False)

    def _ask_copilot(self) -> None:
        if not self._selected_node:
            return
        self._context.go_to(
            Route.COPILOT,
            {
                "focus": self._selected_node,
                "kind": "artifact",
                "origin": Route.GRAPH_EXPLORER,
            },
        )

    def _on_edge_details(self, edge: object) -> None:
        if edge is None or isinstance(edge, GraphEdgeView):
            self._rel_details.set_edge(edge)

    def _on_search_results(self, result: object) -> None:
        if not isinstance(result, GraphSearchResult):
            return
        self._search.set_results(result)
        if result.focus_id:
            self._vm.focus(result.focus_id)
            self._canvas.highlight_nodes(m.node_id for m in result.matches)

    def _on_busy(self, busy: bool) -> None:
        if busy:
            self._status.setText("Loading\u2026")

    def _on_error(self, message: str) -> None:
        self._status.setText(message)

    def _on_canvas_metrics(self, metrics: object) -> None:
        if isinstance(metrics, dict):
            self._metrics.update({k: float(v) for k, v in metrics.items()})
            self._analytics.set_metrics(self._metrics)

    def _on_expand_metric(self, latency_ms: float) -> None:
        self._metrics["expand_ms"] = latency_ms
        self._analytics.set_metrics(self._metrics)

    def _on_vm_metrics(self, metrics: object) -> None:
        if isinstance(metrics, dict):
            self._metrics.update({k: float(v) for k, v in metrics.items()})
            self._analytics.set_metrics(self._metrics)

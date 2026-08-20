"""Intelligence graph routes.

Exposes the Knowledge Graph for interactive exploration through the Graph
Explorer service. Every endpoint returns presentation-oriented DTOs — domain
graph objects are never serialized directly. The router is thin: it maps request
parameters to service calls and service view DTOs to response models.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from core.domain.graph_view import (
    GraphAnalyticsSummary,
    GraphNodeView,
    GraphPathView,
    GraphSearchResult,
    GraphSelection,
    GraphSnapshotView,
    GraphView,
)
from services.graph import GraphExplorerService

_NOT_FOUND = 404


class NodeViewModel(BaseModel):
    """A display-ready graph node."""

    node_id: str
    node_type: str
    label: str
    tone: str
    risk_percent: int
    degree: int
    labels: list[str]
    metadata: dict[str, str]


class EdgeViewModel(BaseModel):
    """A display-ready graph relationship."""

    edge_id: str
    source_id: str
    target_id: str
    relationship: str
    confidence: float
    provenance: str
    timestamp: str


class GraphViewModel(BaseModel):
    """A bounded subgraph."""

    root_id: str
    nodes: list[NodeViewModel]
    edges: list[EdgeViewModel]
    truncated: bool
    node_count: int
    edge_count: int


class SelectionModel(BaseModel):
    """A focus node with its neighbourhood identifiers."""

    focus_id: str
    neighbor_ids: list[str]
    edge_ids: list[str]


class PathViewModel(BaseModel):
    """A traversal path between two nodes."""

    source_id: str
    target_id: str
    found: bool
    length: int
    nodes: list[NodeViewModel]
    edges: list[EdgeViewModel]


class SnapshotModel(BaseModel):
    """A point-in-time graph summary."""

    node_count: int
    edge_count: int
    duplicate_suppressions: int
    node_type_counts: list[list[str | int]]
    relationship_type_counts: list[list[str | int]]


class ConnectedEntityModel(BaseModel):
    """A node paired with its connection count."""

    node: NodeViewModel
    degree: int


class AnalyticsModel(BaseModel):
    """Lightweight graph analytics."""

    node_count: int
    edge_count: int
    ioc_count: int
    node_type_counts: list[list[str | int]]
    relationship_type_counts: list[list[str | int]]
    most_connected: list[ConnectedEntityModel]
    largest_component_size: int
    component_count: int
    reachable_from_top: int
    density: float


class SearchModel(BaseModel):
    """A graph search result with an auto-focus target."""

    query: str
    focus_id: str
    matches: list[NodeViewModel]
    match_count: int


def _service(request: Request) -> GraphExplorerService:
    service: GraphExplorerService = request.app.state.graph_explorer_service
    return service


def _node_model(view: GraphNodeView) -> NodeViewModel:
    return NodeViewModel(
        node_id=view.node_id,
        node_type=view.node_type,
        label=view.label,
        tone=view.tone,
        risk_percent=view.risk_percent,
        degree=view.degree,
        labels=list(view.labels),
        metadata=dict(view.metadata),
    )


def _graph_model(view: GraphView) -> GraphViewModel:
    return GraphViewModel(
        root_id=view.root_id,
        nodes=[_node_model(n) for n in view.nodes],
        edges=[
            EdgeViewModel(
                edge_id=e.edge_id,
                source_id=e.source_id,
                target_id=e.target_id,
                relationship=e.relationship,
                confidence=e.confidence,
                provenance=e.provenance,
                timestamp=e.timestamp,
            )
            for e in view.edges
        ],
        truncated=view.truncated,
        node_count=view.node_count,
        edge_count=view.edge_count,
    )


def _path_model(view: GraphPathView) -> PathViewModel:
    return PathViewModel(
        source_id=view.source_id,
        target_id=view.target_id,
        found=view.found,
        length=view.length,
        nodes=[_node_model(n) for n in view.nodes],
        edges=[
            EdgeViewModel(
                edge_id=e.edge_id,
                source_id=e.source_id,
                target_id=e.target_id,
                relationship=e.relationship,
                confidence=e.confidence,
                provenance=e.provenance,
                timestamp=e.timestamp,
            )
            for e in view.edges
        ],
    )


def _snapshot_model(view: GraphSnapshotView) -> SnapshotModel:
    return SnapshotModel(
        node_count=view.node_count,
        edge_count=view.edge_count,
        duplicate_suppressions=view.duplicate_suppressions,
        node_type_counts=[[name, count] for name, count in view.node_type_counts],
        relationship_type_counts=[[name, count] for name, count in view.relationship_type_counts],
    )


def _analytics_model(view: GraphAnalyticsSummary) -> AnalyticsModel:
    return AnalyticsModel(
        node_count=view.node_count,
        edge_count=view.edge_count,
        ioc_count=view.ioc_count,
        node_type_counts=[[name, count] for name, count in view.node_type_counts],
        relationship_type_counts=[[name, count] for name, count in view.relationship_type_counts],
        most_connected=[
            ConnectedEntityModel(node=_node_model(entity.node), degree=entity.degree)
            for entity in view.most_connected
        ],
        largest_component_size=view.largest_component_size,
        component_count=view.component_count,
        reachable_from_top=view.reachable_from_top,
        density=view.density,
    )


def _search_model(view: GraphSearchResult) -> SearchModel:
    return SearchModel(
        query=view.query,
        focus_id=view.focus_id,
        matches=[_node_model(n) for n in view.matches],
        match_count=view.match_count,
    )


def _selection_model(view: GraphSelection) -> SelectionModel:
    return SelectionModel(
        focus_id=view.focus_id,
        neighbor_ids=list(view.neighbor_ids),
        edge_ids=list(view.edge_ids),
    )


def build_router() -> APIRouter:
    """Build the intelligence graph router."""
    router = APIRouter(prefix="/api/graph", tags=["graph"])

    @router.get("/snapshot", response_model=SnapshotModel)
    def snapshot(request: Request) -> SnapshotModel:
        """Return a point-in-time summary of the whole graph."""
        return _snapshot_model(_service(request).snapshot())

    @router.get("/analytics", response_model=AnalyticsModel)
    def analytics(request: Request, top: int = Query(5, ge=1, le=50)) -> AnalyticsModel:
        """Return lightweight graph analytics."""
        return _analytics_model(_service(request).analytics(top=top))

    @router.get("/search", response_model=SearchModel)
    def search(
        request: Request,
        q: str = Query(..., min_length=1),
        limit: int = Query(25, ge=1, le=200),
    ) -> SearchModel:
        """Search the graph and return matches with an auto-focus target."""
        return _search_model(_service(request).search(q, limit=limit))

    @router.get("/path", response_model=PathViewModel)
    def path(
        request: Request,
        source: str = Query(..., min_length=1),
        target: str = Query(..., min_length=1),
    ) -> PathViewModel:
        """Return the shortest path between two nodes."""
        return _path_model(_service(request).shortest_path(source, target))

    @router.get("/shared-iocs", response_model=GraphViewModel)
    def shared_iocs(
        request: Request,
        a: str = Query(..., min_length=1),
        b: str = Query(..., min_length=1),
    ) -> GraphViewModel:
        """Return a view of two nodes and the IOCs they share."""
        return _graph_model(_service(request).shared_iocs(a, b))

    @router.get("/investigation/{root_id}", response_model=GraphViewModel)
    def investigation(
        root_id: str, request: Request, depth: int = Query(2, ge=1, le=6)
    ) -> GraphViewModel:
        """Return the subgraph reachable from an investigation root."""
        return _graph_model(_service(request).investigation_graph(root_id, depth=depth))

    @router.get("/incident/{incident_id}", response_model=GraphViewModel)
    def incident(incident_id: str, request: Request) -> GraphViewModel:
        """Return the neighbourhood of an incident node."""
        return _graph_model(_service(request).incident_graph(incident_id))

    @router.get("/campaign/{campaign_id}", response_model=GraphViewModel)
    def campaign(campaign_id: str, request: Request) -> GraphViewModel:
        """Return the neighbourhood of a campaign node."""
        return _graph_model(_service(request).campaign_graph(campaign_id))

    @router.get("/nodes/{node_id}", response_model=NodeViewModel)
    def node(node_id: str, request: Request) -> NodeViewModel:
        """Return a single node, or 404 if it does not exist."""
        found = _service(request).node(node_id)
        if found is None:
            raise HTTPException(status_code=_NOT_FOUND, detail="Node not found")
        return _node_model(found)

    @router.get("/nodes/{node_id}/neighbors", response_model=GraphViewModel)
    def neighbors(
        node_id: str, request: Request, depth: int = Query(1, ge=1, le=6)
    ) -> GraphViewModel:
        """Expand a node's neighbourhood up to ``depth`` hops."""
        return _graph_model(_service(request).expand(node_id, depth=depth))

    @router.get("/nodes/{node_id}/selection", response_model=SelectionModel)
    def selection(node_id: str, request: Request) -> SelectionModel:
        """Return a lightweight selection descriptor for a focus node."""
        return _selection_model(_service(request).selection(node_id))

    return router


__all__ = ["build_router"]

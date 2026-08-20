"""Tests for the BackendClient graph gateway and DTO reconstruction (M9-P3-A)."""

from __future__ import annotations

import pytest

from application.api import graph as graph_api
from core.domain.events import (
    artifact_analyzed,
    incident_created,
    relationship_discovered,
)
from infrastructure.graph import InMemoryGraphRepository
from services.events import InProcessEventBus
from services.graph import GraphBuilder, GraphExplorerService, GraphQueryService
from ui.backend import (
    BackendClient,
    GraphAnalyticsSummary,
    GraphPathView,
    GraphSnapshotView,
    GraphView,
)
from ui.backend.client import (
    _parse_analytics,
    _parse_graph_view,
    _parse_node_view,
    _parse_path_view,
    _parse_search,
    _parse_selection,
    _parse_snapshot_view,
)

pytestmark = pytest.mark.ui


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def bind(self, **k: object) -> _FakeLogger:
        return self


def _explorer() -> GraphExplorerService:
    repo = InMemoryGraphRepository()
    bus = InProcessEventBus(_FakeLogger())
    GraphBuilder(repo, _FakeLogger()).attach(bus)
    bus.publish(
        artifact_analyzed(
            source="url-analysis",
            artifact_id="url-1",
            artifact_type="url",
            verdict="phishing",
            risk_score=0.9,
            category="credential_harvesting",
        )
    )
    bus.publish(
        incident_created(
            source="corr", incident_id="inc-1", incident_title="Phishing", artifact_id="url-1"
        )
    )
    bus.publish(
        relationship_discovered(
            source="ioc",
            source_id="url-1",
            source_type="url",
            target_id="ioc-1",
            target_type="ioc",
            relationship="shares_ioc",
        )
    )
    return GraphExplorerService(GraphQueryService(repo), repo, _FakeLogger())


# --- round-trip: API model -> JSON -> client DTO ------------------------


def test_node_view_round_trip() -> None:
    ex = _explorer()
    node = ex.node("url-1")
    assert node is not None
    payload = graph_api._node_model(node).model_dump()
    parsed = _parse_node_view(payload)
    assert parsed.node_id == "url-1"
    assert parsed.tone == "danger"
    assert parsed.risk_percent == 90
    assert parsed.metadata == node.metadata


def test_graph_view_round_trip() -> None:
    ex = _explorer()
    payload = graph_api._graph_model(ex.neighbors("url-1")).model_dump()
    parsed = _parse_graph_view(payload)
    assert isinstance(parsed, GraphView)
    assert parsed.root_id == "url-1"
    ids = {n.node_id for n in parsed.nodes}
    assert "url-1" in ids
    for edge in parsed.edges:
        assert edge.source_id in ids
        assert edge.target_id in ids


def test_snapshot_round_trip() -> None:
    ex = _explorer()
    payload = graph_api._snapshot_model(ex.snapshot()).model_dump()
    parsed = _parse_snapshot_view(payload)
    assert isinstance(parsed, GraphSnapshotView)
    assert parsed.node_count >= 3
    assert dict(parsed.node_type_counts).get("ioc") == 1


def test_path_round_trip() -> None:
    ex = _explorer()
    payload = graph_api._path_model(ex.shortest_path("ioc-1", "inc-1")).model_dump()
    parsed = _parse_path_view(payload)
    assert isinstance(parsed, GraphPathView)
    assert parsed.found
    assert parsed.nodes[0].node_id == "ioc-1"
    assert parsed.nodes[-1].node_id == "inc-1"


def test_analytics_round_trip() -> None:
    ex = _explorer()
    payload = graph_api._analytics_model(ex.analytics()).model_dump()
    parsed = _parse_analytics(payload)
    assert isinstance(parsed, GraphAnalyticsSummary)
    assert parsed.ioc_count == 1
    assert parsed.most_connected
    assert parsed.most_connected[0].degree >= 1
    # P3-C additive fields survive the API→client round-trip.
    assert parsed.relationship_type_counts
    assert parsed.component_count >= 1
    assert 0.0 <= parsed.density <= 1.0


def test_search_round_trip() -> None:
    ex = _explorer()
    payload = graph_api._search_model(ex.search("url")).model_dump()
    parsed = _parse_search(payload)
    assert parsed.match_count >= 1
    assert parsed.focus_id == parsed.matches[0].node_id


def test_selection_round_trip() -> None:
    ex = _explorer()
    payload = graph_api._selection_model(ex.selection("url-1")).model_dump()
    parsed = _parse_selection(payload)
    assert parsed.focus_id == "url-1"
    assert len(parsed.neighbor_ids) >= 1


# --- error handling: unreachable backend -> safe defaults ---------------


def _dead_client() -> BackendClient:
    return BackendClient("http://127.0.0.1:9")


def test_client_graph_methods_default_on_error() -> None:
    client = _dead_client()
    assert client.graph_snapshot() == GraphSnapshotView()
    assert client.graph_node("x") is None
    assert client.graph_neighbors("x").root_id == "x"
    assert client.graph_neighbors("x").node_count == 0
    assert client.graph_analytics().most_connected == ()
    assert client.graph_search("q").query == "q"
    assert client.graph_search("q").match_count == 0
    assert client.graph_shortest_path("a", "b").found is False
    assert client.graph_shared_iocs("a", "b").root_id == "a"
    assert client.graph_investigation("root").root_id == "root"
    assert client.graph_incident("inc").root_id == "inc"
    assert client.graph_campaign("camp").root_id == "camp"
    assert client.graph_selection("n").focus_id == "n"

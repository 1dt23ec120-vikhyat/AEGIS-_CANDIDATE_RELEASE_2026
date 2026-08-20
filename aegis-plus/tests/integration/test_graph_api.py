"""Integration tests for the intelligence graph API (M9-P3-A)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from application.api import graph
from core.domain.events import (
    artifact_analyzed,
    campaign_created,
    incident_created,
    relationship_discovered,
    threat_recorded,
)
from infrastructure.graph import InMemoryGraphRepository
from services.events import InProcessEventBus
from services.graph import GraphBuilder, GraphExplorerService, GraphQueryService


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def bind(self, **k: object) -> _FakeLogger:
        return self


@pytest.fixture
def client() -> Iterator[TestClient]:
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
        artifact_analyzed(
            source="file-analysis",
            artifact_id="file-1",
            artifact_type="file",
            verdict="legitimate",
            risk_score=0.1,
            category="none",
        )
    )
    bus.publish(threat_recorded(source="ti", artifact_id="url-1", artifact_type="url"))
    bus.publish(
        incident_created(
            source="corr", incident_id="inc-1", incident_title="Phishing", artifact_id="url-1"
        )
    )
    bus.publish(campaign_created(source="corr", campaign_id="camp-1", campaign_name="Camp A"))
    for artifact, atype in (("url-1", "url"), ("file-1", "file")):
        bus.publish(
            relationship_discovered(
                source="ioc",
                source_id=artifact,
                source_type=atype,
                target_id="ioc-1",
                target_type="ioc",
                relationship="shares_ioc",
            )
        )
    explorer = GraphExplorerService(GraphQueryService(repo), repo, _FakeLogger())
    app = FastAPI()
    app.state.graph_explorer_service = explorer
    app.include_router(graph.build_router())
    with TestClient(app) as test_client:
        yield test_client


def test_snapshot_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/snapshot")
    assert response.status_code == 200
    body = response.json()
    assert body["node_count"] >= 6
    assert body["edge_count"] >= 4
    assert any(pair == ["ioc", 1] for pair in body["node_type_counts"])


def test_node_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/nodes/url-1")
    assert response.status_code == 200
    body = response.json()
    assert body["node_id"] == "url-1"
    assert body["tone"] == "danger"
    assert body["risk_percent"] == 90


def test_node_endpoint_404(client: TestClient) -> None:
    response = client.get("/api/graph/nodes/missing")
    assert response.status_code == 404


def test_neighbors_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/nodes/url-1/neighbors", params={"depth": 1})
    assert response.status_code == 200
    body = response.json()
    ids = {n["node_id"] for n in body["nodes"]}
    assert "url-1" in ids
    assert body["node_count"] == len(body["nodes"])


def test_selection_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/nodes/url-1/selection")
    assert response.status_code == 200
    body = response.json()
    assert body["focus_id"] == "url-1"
    assert len(body["neighbor_ids"]) >= 2


def test_path_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/path", params={"source": "file-1", "target": "inc-1"})
    assert response.status_code == 200
    body = response.json()
    assert body["found"] is True
    assert body["nodes"][0]["node_id"] == "file-1"
    assert body["nodes"][-1]["node_id"] == "inc-1"


def test_shared_iocs_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/shared-iocs", params={"a": "url-1", "b": "file-1"})
    assert response.status_code == 200
    ids = {n["node_id"] for n in response.json()["nodes"]}
    assert "ioc-1" in ids


def test_investigation_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/investigation/url-1", params={"depth": 2})
    assert response.status_code == 200
    ids = {n["node_id"] for n in response.json()["nodes"]}
    assert {"url-1", "inc-1"}.issubset(ids)


def test_incident_and_campaign_endpoints(client: TestClient) -> None:
    inc = client.get("/api/graph/incident/inc-1")
    assert inc.status_code == 200
    assert any(n["node_id"] == "url-1" for n in inc.json()["nodes"])
    camp = client.get("/api/graph/campaign/camp-1")
    assert camp.status_code == 200
    assert camp.json()["root_id"] == "camp-1"


def test_search_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/search", params={"q": "url"})
    assert response.status_code == 200
    body = response.json()
    assert body["match_count"] >= 1
    assert body["focus_id"] == body["matches"][0]["node_id"]


def test_search_endpoint_requires_query(client: TestClient) -> None:
    response = client.get("/api/graph/search", params={"q": ""})
    assert response.status_code == 422  # min_length=1


def test_analytics_endpoint(client: TestClient) -> None:
    response = client.get("/api/graph/analytics", params={"top": 3})
    assert response.status_code == 200
    body = response.json()
    assert body["ioc_count"] == 1
    assert body["most_connected"]
    assert body["most_connected"][0]["degree"] >= 1
    assert body["largest_component_size"] >= 2
    # P3-C additive fields.
    assert body["relationship_type_counts"]
    assert body["component_count"] >= 1
    assert 0.0 <= body["density"] <= 1.0

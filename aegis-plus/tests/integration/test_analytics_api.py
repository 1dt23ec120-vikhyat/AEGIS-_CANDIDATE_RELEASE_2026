"""Integration tests for the advanced analytics API (M11 Phase E)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from application.api import analytics
from core.domain.events import (
    artifact_analyzed,
    campaign_created,
    incident_created,
    relationship_discovered,
    threat_recorded,
)
from infrastructure.graph import InMemoryGraphRepository
from services.analytics import (
    AnalyticsOverviewService,
    AttackAnalysisService,
    CampaignIntelligenceService,
    GraphAnalyticsService,
    GraphOverlayService,
    IOCIntelligenceService,
    RecommendationService,
    ThreatScoringService,
)
from services.events import InProcessEventBus
from services.graph import GraphBuilder, GraphQueryService


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
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
            verdict="malicious",
            risk_score=0.8,
            category="malware",
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
        bus.publish(
            relationship_discovered(
                source="corr",
                source_id="camp-1",
                source_type="campaign",
                target_id=artifact,
                target_type=atype,
                relationship="associated_with",
            )
        )

    query = GraphQueryService(repo)
    analyticsvc = GraphAnalyticsService(query, _FakeLogger())
    ioc = IOCIntelligenceService(query, _FakeLogger())
    campaign = CampaignIntelligenceService(query, _FakeLogger())
    scoring = ThreatScoringService(query, analyticsvc, _FakeLogger())
    attack = AttackAnalysisService(query, analyticsvc, _FakeLogger())
    recommend = RecommendationService(analyticsvc, ioc, campaign, scoring, _FakeLogger())
    overview = AnalyticsOverviewService(scoring, campaign, ioc, attack, recommend, _FakeLogger())
    overlay = GraphOverlayService(query, analyticsvc, attack, _FakeLogger())

    app = FastAPI()
    app.state.analytics_overview_service = overview
    app.state.graph_overlay_service = overlay
    app.include_router(analytics.build_router())
    with TestClient(app) as test_client:
        yield test_client


def test_overview_endpoint(client: TestClient) -> None:
    response = client.get("/api/analytics/overview", params={"top": 5})
    assert response.status_code == 200
    body = response.json()
    assert body["threat_priorities"]
    assert body["emerging_campaigns"]
    assert body["ioc_trends"]
    assert body["infrastructure_reuse"]
    assert body["threat_distribution"]
    assert body["recommendations"]
    # Explainability is carried through the API.
    assert body["threat_priorities"][0]["rationale"]


def test_overview_validation(client: TestClient) -> None:
    assert client.get("/api/analytics/overview", params={"top": 0}).status_code == 422


def test_overlay_endpoint(client: TestClient) -> None:
    response = client.get("/api/analytics/overlay", params={"top": 10})
    assert response.status_code == 200
    body = response.json()
    assert body["nodes"]
    assert body["critical_ids"]
    assert body["top_central"]
    url_overlay = next(n for n in body["nodes"] if n["node_id"] == "url-1")
    assert url_overlay["cluster_id"] == "ioc-1"  # url-1 is a member of the shared-IOC cluster
    assert url_overlay["campaign_id"] == "camp-1"

"""Integration tests for the AI Security Copilot API (M12 Phase 1).

Wires the real pipeline over a small in-memory graph with a fake LLM provider and
drives it through the FastAPI router, confirming grounded answers, graceful
degradation when the provider is unavailable, focus updates, and session
inspection and closure.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from application.api import copilot
from core.domain.events import (
    artifact_analyzed,
    campaign_created,
    incident_created,
    relationship_discovered,
    threat_recorded,
)
from core.interfaces.llm_provider import ILLMProvider, LLMRequest, LLMResult
from infrastructure.graph import InMemoryGraphRepository
from services.analytics import (
    AnalyticsOverviewService,
    AttackAnalysisService,
    CampaignIntelligenceService,
    GraphAnalyticsService,
    IOCIntelligenceService,
    RecommendationService,
    ThreatScoringService,
)
from services.copilot import (
    CitationValidator,
    ContextCollector,
    CopilotOrchestrator,
    GroundingValidator,
    IntentDetector,
    PromptBuilder,
    ResponseFormatter,
    SessionManager,
    build_default_registry,
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


class _FakeProvider(ILLMProvider):
    def __init__(self, *, available: bool = True) -> None:
        self._available = available

    def complete(self, request: LLMRequest) -> LLMResult:
        marker = ""
        for line in request.system_prompt.splitlines():
            if line.startswith("[1] (cite: "):
                key = line.split("(cite: ", 1)[1].split(")", 1)[0]
                marker = f"[cite:{key}]"
                break
        return LLMResult(
            text=f"Grounded answer. {marker}".strip(),
            model_id="fake-1",
            prompt_tokens=8,
            completion_tokens=3,
            success=True,
        )

    def model_id(self) -> str:
        return "fake-1"

    def provider_name(self) -> str:
        return "fake"

    def is_available(self) -> bool:
        return self._available


def _seed() -> GraphQueryService:
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
    bus.publish(threat_recorded(source="ti", artifact_id="url-1", artifact_type="url"))
    bus.publish(
        incident_created(
            source="corr", incident_id="inc-1", incident_title="Phishing", artifact_id="url-1"
        )
    )
    bus.publish(campaign_created(source="corr", campaign_id="camp-1", campaign_name="Camp A"))
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
    return GraphQueryService(repo)


def _build_client(provider: ILLMProvider) -> TestClient:
    query = _seed()
    analytics = GraphAnalyticsService(query, _FakeLogger())
    ioc = IOCIntelligenceService(query, _FakeLogger())
    campaign = CampaignIntelligenceService(query, _FakeLogger())
    scoring = ThreatScoringService(query, analytics, _FakeLogger())
    attack = AttackAnalysisService(query, analytics, _FakeLogger())
    recommend = RecommendationService(analytics, ioc, campaign, scoring, _FakeLogger())
    overview = AnalyticsOverviewService(scoring, campaign, ioc, attack, recommend, _FakeLogger())
    collector = ContextCollector(
        query, analytics, ioc, campaign, scoring, attack, recommend, overview, _FakeLogger()
    )
    sessions = SessionManager()
    orchestrator = CopilotOrchestrator(
        IntentDetector(),
        build_default_registry(),
        collector,
        PromptBuilder(),
        provider,
        CitationValidator(),
        GroundingValidator(),
        ResponseFormatter(),
        sessions,
        _FakeLogger(),
    )
    app = FastAPI()
    app.state.copilot_orchestrator = orchestrator
    app.state.copilot_sessions = sessions
    app.include_router(copilot.build_router())
    return TestClient(app)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with _build_client(_FakeProvider()) as test_client:
        yield test_client


def test_ask_returns_grounded_answer(client: TestClient) -> None:
    response = client.post(
        "/api/copilot/ask",
        json={"question": "why is url-1 malicious?", "artifact_id": "url-1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is True
    assert body["citations"]
    assert body["prompt_metadata"]["skill_id"] == "threat_investigation"
    assert body["session_id"]
    assert "[cite:" not in body["answer"]


def test_ask_validation_rejects_empty_question(client: TestClient) -> None:
    assert client.post("/api/copilot/ask", json={"question": ""}).status_code == 422


def test_ask_provider_unavailable_degrades() -> None:
    with _build_client(_FakeProvider(available=False)) as client:
        body = client.post("/api/copilot/ask", json={"question": "status?"}).json()
        assert body["available"] is False


def test_focus_update_and_session_inspection(client: TestClient) -> None:
    first = client.post(
        "/api/copilot/ask",
        json={"question": "why is url-1 malicious?", "artifact_id": "url-1"},
    ).json()
    session_id = first["session_id"]

    focus = client.post(
        f"/api/copilot/session/{session_id}/focus",
        json={"current_artifact_id": "url-1"},
    )
    assert focus.status_code == 204

    got = client.get(f"/api/copilot/session/{session_id}")
    assert got.status_code == 200
    assert got.json()["turns"]


def test_session_not_found(client: TestClient) -> None:
    assert client.get("/api/copilot/session/ghost").status_code == 404


def test_close_session(client: TestClient) -> None:
    first = client.post(
        "/api/copilot/ask",
        json={"question": "why is url-1 malicious?", "artifact_id": "url-1"},
    ).json()
    session_id = first["session_id"]
    assert client.delete(f"/api/copilot/session/{session_id}").status_code == 204
    assert client.delete(f"/api/copilot/session/{session_id}").status_code == 404

"""Tests for Copilot streaming — provider, orchestrator, and API (M12 Phase 3).

Streaming is exercised without network access using fakes. The central guarantee
verified here: streaming delivers raw tokens progressively, but the terminal
``final`` event carries the *grounding-validated* response — grounding and
citations are enforced on the complete text exactly as in the non-streaming path
(ADR-0002).
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from fastapi import FastAPI
from fastapi.testclient import TestClient

from application.api import copilot as copilot_api
from core.domain.copilot import CopilotQuery
from core.domain.events import artifact_analyzed, relationship_discovered, threat_recorded
from core.interfaces.llm_provider import (
    ILLMProvider,
    LLMRequest,
    LLMResult,
    LLMStreamChunk,
)
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


class _StreamingProvider(ILLMProvider):
    """A provider that streams a citation-bearing answer token by token."""

    def __init__(self, *, available: bool = True, supports: bool = True) -> None:
        self._available = available
        self._supports = supports

    def _text(self, request: LLMRequest) -> str:
        marker = ""
        for line in request.system_prompt.splitlines():
            if line.startswith("[1] (cite: "):
                key = line.split("(cite: ", 1)[1].split(")", 1)[0]
                marker = f"[cite:{key}]"
                break
        return f"Streamed grounded answer. {marker}".strip()

    def complete(self, request: LLMRequest) -> LLMResult:
        return LLMResult(text=self._text(request), model_id="fake-1", success=True)

    def stream(self, request: LLMRequest) -> Iterator[LLMStreamChunk]:
        text = self._text(request)
        for word in text.split(" "):
            yield LLMStreamChunk(text=word + " ")
        yield LLMStreamChunk(done=True, success=True, completion_tokens=5, latency_ms=1.0)

    def model_id(self) -> str:
        return "fake-1"

    def provider_name(self) -> str:
        return "fake"

    def is_available(self) -> bool:
        return self._available

    def supports_streaming(self) -> bool:
        return self._supports


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


def _orchestrator(provider: ILLMProvider) -> CopilotOrchestrator:
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
    return CopilotOrchestrator(
        IntentDetector(),
        build_default_registry(),
        collector,
        PromptBuilder(),
        provider,
        CitationValidator(),
        GroundingValidator(),
        ResponseFormatter(),
        SessionManager(),
        _FakeLogger(),
    )


# --- provider ------------------------------------------------------------


def test_default_provider_stream_unsupported() -> None:
    class _Bare(ILLMProvider):
        def complete(self, request: LLMRequest) -> LLMResult:
            return LLMResult()

        def model_id(self) -> str:
            return "x"

        def provider_name(self) -> str:
            return "x"

        def is_available(self) -> bool:
            return True

    chunks = list(_Bare().stream(LLMRequest(system_prompt="s", user_message="u")))
    assert len(chunks) == 1
    assert chunks[0].done and not chunks[0].success


def test_claude_provider_advertises_streaming() -> None:
    from ai.copilot import ClaudeProvider

    provider = ClaudeProvider(
        model="m",
        api_key="",
        base_url="https://api.anthropic.com",
        anthropic_version="2023-06-01",
        timeout_seconds=5.0,
        logger=_FakeLogger(),
    )
    assert provider.supports_streaming() is True
    # Unavailable (no key) → terminal failure chunk, never raises.
    chunks = list(provider.stream(LLMRequest(system_prompt="s", user_message="u")))
    assert chunks[-1].done and not chunks[-1].success


def test_claude_parse_stream_line_text_delta() -> None:
    from ai.copilot import ClaudeProvider

    provider = ClaudeProvider(
        model="m",
        api_key="k",
        base_url="x",
        anthropic_version="v",
        timeout_seconds=5.0,
        logger=_FakeLogger(),
    )
    line = 'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}'
    assert provider._parse_stream_line(line) == ("hi", 0, 0)
    assert provider._parse_stream_line("event: ping") is None
    assert provider._parse_stream_line("data: [DONE]") is None


# --- orchestrator --------------------------------------------------------


def test_stream_ask_yields_tokens_then_grounded_final() -> None:
    orch = _orchestrator(_StreamingProvider())
    events = list(
        orch.stream_ask(CopilotQuery(question="why is url-1 malicious?", artifact_id="url-1"))
    )
    tokens = [e for e in events if e.kind == "token"]
    finals = [e for e in events if e.kind == "final"]
    assert tokens
    assert len(finals) == 1
    final = finals[0]
    assert final.response is not None
    # Grounding was enforced on the complete streamed text.
    assert final.response.is_grounded
    assert final.response.citations
    # Citation markers are stripped from the finalized answer.
    assert "[cite:" not in final.response.answer


def test_stream_ask_records_turn() -> None:
    orch = _orchestrator(_StreamingProvider())
    events = list(orch.stream_ask(CopilotQuery(question="why?", artifact_id="url-1")))
    finals = [e for e in events if e.kind == "final" and e.response is not None]
    assert finals
    session_id = finals[0].response.session_id  # type: ignore[union-attr]
    session = orch._sessions.get(session_id)
    assert session is not None
    assert len(session.turns) == 1


def test_stream_ask_unsupported_provider_emits_error() -> None:
    orch = _orchestrator(_StreamingProvider(supports=False))
    events = list(orch.stream_ask(CopilotQuery(question="why?", artifact_id="url-1")))
    assert events
    assert events[-1].kind == "error"
    assert events[-1].response is not None
    assert events[-1].response.available is False


def test_stream_ask_provider_failure_emits_error() -> None:
    class _Failing(_StreamingProvider):
        def stream(self, request: LLMRequest) -> Iterator[LLMStreamChunk]:
            yield LLMStreamChunk(text="partial ")
            yield LLMStreamChunk(done=True, success=False, error="mid-stream boom")

    orch = _orchestrator(_Failing())
    events = list(orch.stream_ask(CopilotQuery(question="why?", artifact_id="url-1")))
    assert any(e.kind == "token" for e in events)
    assert events[-1].kind == "error"


# --- API -----------------------------------------------------------------


def _client(provider: ILLMProvider) -> TestClient:
    orch = _orchestrator(provider)
    app = FastAPI()
    app.state.copilot_orchestrator = orch
    app.state.copilot_sessions = orch._sessions
    app.include_router(copilot_api.build_router())
    return TestClient(app)


def test_api_stream_returns_sse_events() -> None:
    with (
        _client(_StreamingProvider()) as client,
        client.stream(
            "POST",
            "/api/copilot/ask/stream",
            json={"question": "why is url-1 malicious?", "artifact_id": "url-1"},
        ) as response,
    ):
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        kinds: list[str] = []
        final_payload: dict[str, object] = {}
        for raw_line in response.iter_lines():
            line = raw_line.strip()
            if not line.startswith("data:"):
                continue
            data = json.loads(line[len("data:") :].strip())
            kinds.append(str(data["kind"]))
            if data["kind"] == "final":
                final_payload = data["response"]
    assert "token" in kinds
    assert "final" in kinds
    assert final_payload.get("available") is True
    assert final_payload.get("citations")

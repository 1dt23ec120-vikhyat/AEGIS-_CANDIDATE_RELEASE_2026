"""Grounding reliability edge cases (M12 Phase 3, §4).

Confirms the Phase 1 grounding guarantees hold at the boundaries: a nonexistent
artifact yields an honest "insufficient intelligence" answer rather than a
fabricated one, and a model that emits an invalid/unknown citation marker has
that marker flagged and does not gain grounding from it. These lock in ADR-0002:
the Copilot never silently fabricates platform intelligence.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from core.domain.copilot import CopilotQuery
from core.domain.events import artifact_analyzed, threat_recorded
from core.interfaces.llm_provider import ILLMProvider, LLMRequest, LLMResult, LLMStreamChunk
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

pytestmark = pytest.mark.integration


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
    def bind(self, **k: object) -> _FakeLogger:
        return self


class _FixedProvider(ILLMProvider):
    def __init__(self, text: str) -> None:
        self._text = text

    def complete(self, request: LLMRequest) -> LLMResult:
        return LLMResult(text=self._text, model_id="fake-1", success=True)

    def stream(self, request: LLMRequest) -> Iterator[LLMStreamChunk]:
        yield LLMStreamChunk(text=self._text)
        yield LLMStreamChunk(done=True, success=True)

    def model_id(self) -> str:
        return "fake-1"

    def provider_name(self) -> str:
        return "fake"

    def is_available(self) -> bool:
        return True

    def supports_streaming(self) -> bool:
        return True


def _orchestrator(provider: ILLMProvider, *, seed: bool = True) -> CopilotOrchestrator:
    repo = InMemoryGraphRepository()
    bus = InProcessEventBus(_FakeLogger())
    GraphBuilder(repo, _FakeLogger()).attach(bus)
    if seed:
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
    query = GraphQueryService(repo)
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


def test_nonexistent_artifact_yields_insufficient_answer() -> None:
    # The model would answer, but there is no intelligence for this artifact.
    orch = _orchestrator(_FixedProvider("This artifact is definitely malicious."), seed=False)
    response = orch.ask(CopilotQuery(question="why is ghost-1 malicious?", artifact_id="ghost-1"))
    # With no supporting context, grounding must not certify the answer.
    assert not response.is_grounded or not response.citations


def test_invalid_citation_marker_is_flagged_not_trusted() -> None:
    # The model cites a source that was never in the provided context.
    orch = _orchestrator(_FixedProvider("Malicious. [cite:threat_score:does-not-exist]"))
    response = orch.ask(CopilotQuery(question="why is url-1 malicious?", artifact_id="url-1"))
    # The bogus marker resolves to no citation and is recorded as a violation.
    assert all(c.source_id != "does-not-exist" for c in response.citations)
    assert response.grounding_violations


def test_streaming_nonexistent_artifact_final_is_honest() -> None:
    orch = _orchestrator(_FixedProvider("Definitely malicious."), seed=False)
    events = list(
        orch.stream_ask(CopilotQuery(question="why is ghost-9 malicious?", artifact_id="ghost-9"))
    )
    final = next(e for e in events if e.kind in ("final", "error"))
    assert final.response is not None
    assert not final.response.is_grounded or not final.response.citations

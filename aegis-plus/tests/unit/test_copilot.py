"""Unit tests for the AI Security Copilot pipeline (M12 Phase 1).

Each pipeline stage is exercised in isolation with deterministic fakes: intent
detection, skill selection, context collection over the real analytics engine on
a small in-memory graph, prompt building, citation and grounding validation, the
formatter, the session manager, and the orchestrator end to end with a fake LLM
provider.
"""

from __future__ import annotations

import pytest

from core.domain.copilot import (
    ContextItem,
    CopilotQuery,
    DetectedIntent,
    IntentKind,
)
from core.domain.copilot_session import FocusState
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
    """A deterministic LLM provider that echoes a citation for the first item."""

    def __init__(self, *, available: bool = True, text: str | None = None) -> None:
        self._available = available
        self._text = text
        self.last_request: LLMRequest | None = None

    def complete(self, request: LLMRequest) -> LLMResult:
        self.last_request = request
        if self._text is not None:
            return LLMResult(text=self._text, model_id="fake-1", success=True)
        # Derive a citation from the first context block if present.
        marker = ""
        for line in request.system_prompt.splitlines():
            if line.startswith("[1] (cite: "):
                key = line.split("(cite: ", 1)[1].split(")", 1)[0]
                marker = f"[cite:{key}]"
                break
        return LLMResult(
            text=f"This is grounded. {marker}".strip(),
            model_id="fake-1",
            prompt_tokens=10,
            completion_tokens=5,
            success=True,
        )

    def model_id(self) -> str:
        return "fake-1"

    def provider_name(self) -> str:
        return "fake"

    def is_available(self) -> bool:
        return self._available


def _seed_graph() -> GraphQueryService:
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
    return GraphQueryService(repo)


def _collector(query: GraphQueryService) -> ContextCollector:
    analytics = GraphAnalyticsService(query, _FakeLogger())
    ioc = IOCIntelligenceService(query, _FakeLogger())
    campaign = CampaignIntelligenceService(query, _FakeLogger())
    scoring = ThreatScoringService(query, analytics, _FakeLogger())
    attack = AttackAnalysisService(query, analytics, _FakeLogger())
    recommend = RecommendationService(analytics, ioc, campaign, scoring, _FakeLogger())
    overview = AnalyticsOverviewService(scoring, campaign, ioc, attack, recommend, _FakeLogger())
    return ContextCollector(
        query, analytics, ioc, campaign, scoring, attack, recommend, overview, _FakeLogger()
    )


def _orchestrator(provider: ILLMProvider) -> CopilotOrchestrator:
    query = _seed_graph()
    return CopilotOrchestrator(
        IntentDetector(),
        build_default_registry(),
        _collector(query),
        PromptBuilder(),
        provider,
        CitationValidator(),
        GroundingValidator(),
        ResponseFormatter(),
        SessionManager(),
        _FakeLogger(),
    )


# --- intent detection ----------------------------------------------------


def test_intent_ioc_keyword() -> None:
    detector = IntentDetector()
    intent = detector.detect(CopilotQuery(question="Explain this IOC hash"), FocusState())
    assert intent.intent is IntentKind.IOC_INTELLIGENCE
    assert intent.matched_terms


def test_intent_incident_keyword() -> None:
    detector = IntentDetector()
    intent = detector.detect(CopilotQuery(question="What is the root cause?"), FocusState())
    assert intent.intent is IntentKind.INCIDENT_ANALYSIS


def test_intent_falls_back_to_focus_artifact() -> None:
    detector = IntentDetector()
    intent = detector.detect(
        CopilotQuery(question="tell me about it"),
        FocusState(current_artifact_id="url-1"),
    )
    assert intent.intent is IntentKind.THREAT_INVESTIGATION
    assert intent.focus_id == "url-1"
    assert intent.focus_type == "artifact"


def test_intent_defaults_to_executive_summary() -> None:
    detector = IntentDetector()
    intent = detector.detect(CopilotQuery(question="hello there"), FocusState())
    assert intent.intent is IntentKind.EXECUTIVE_SUMMARY


# --- skill registry ------------------------------------------------------


def test_registry_maps_every_intent() -> None:
    registry = build_default_registry()
    for intent in IntentKind:
        skill = registry.for_intent(intent)
        assert skill.spec().intent is intent


def test_registry_skill_ids() -> None:
    assert len(build_default_registry().skill_ids()) == 5


# --- context collection --------------------------------------------------


def test_collect_artifact_scope_includes_threat_score() -> None:
    collector = _collector(_seed_graph())
    registry = build_default_registry()
    spec = registry.for_intent(IntentKind.THREAT_INVESTIGATION).spec()
    intent = DetectedIntent(
        intent=IntentKind.THREAT_INVESTIGATION, focus_id="url-1", focus_type="artifact"
    )
    context = collector.collect(intent, spec, FocusState(current_artifact_id="url-1"))
    assert not context.is_empty
    kinds = {item.kind for item in context.items}
    assert "threat_score" in kinds


def test_collect_global_scope_ranks_by_severity() -> None:
    collector = _collector(_seed_graph())
    spec = build_default_registry().for_intent(IntentKind.EXECUTIVE_SUMMARY).spec()
    intent = DetectedIntent(intent=IntentKind.EXECUTIVE_SUMMARY)
    context = collector.collect(intent, spec, FocusState())
    assert not context.is_empty
    severities = [item.severity for item in context.items]
    assert severities == sorted(severities, reverse=True)


def test_collect_respects_token_budget() -> None:
    query = _seed_graph()
    analytics = GraphAnalyticsService(query, _FakeLogger())
    ioc = IOCIntelligenceService(query, _FakeLogger())
    campaign = CampaignIntelligenceService(query, _FakeLogger())
    scoring = ThreatScoringService(query, analytics, _FakeLogger())
    attack = AttackAnalysisService(query, analytics, _FakeLogger())
    recommend = RecommendationService(analytics, ioc, campaign, scoring, _FakeLogger())
    overview = AnalyticsOverviewService(scoring, campaign, ioc, attack, recommend, _FakeLogger())
    collector = ContextCollector(
        query,
        analytics,
        ioc,
        campaign,
        scoring,
        attack,
        recommend,
        overview,
        _FakeLogger(),
        token_budget=20,
        max_items=2,
    )
    spec = build_default_registry().for_intent(IntentKind.EXECUTIVE_SUMMARY).spec()
    context = collector.collect(
        DetectedIntent(intent=IntentKind.EXECUTIVE_SUMMARY), spec, FocusState()
    )
    assert len(context.items) <= 2


# --- prompt builder ------------------------------------------------------


def test_prompt_includes_context_and_metadata() -> None:
    from core.domain.copilot import CopilotContext

    builder = PromptBuilder()
    items = (ContextItem(kind="threat_score", source_id="url-1", label="url-1", summary="sev 90%"),)
    context = CopilotContext(items=items)
    spec = build_default_registry().for_intent(IntentKind.THREAT_INVESTIGATION).spec()
    built = builder.build(
        CopilotQuery(question="why malicious?"),
        DetectedIntent(intent=IntentKind.THREAT_INVESTIGATION),
        spec,
        "fragment",
        context,
        (),
        model_id="m",
        provider="p",
        temperature=0.1,
    )
    assert "threat_score:url-1" in built.system_prompt
    assert built.metadata.skill_id == "threat_investigation"
    assert built.metadata.context_item_count == 1


# --- citation validation -------------------------------------------------


def test_citation_resolves_present_marker() -> None:
    items = (ContextItem(kind="threat_score", source_id="url-1", label="url-1", summary="sev"),)
    citations, violations = CitationValidator().validate(
        "Grounded. [cite:threat_score:url-1]", items
    )
    assert len(citations) == 1
    assert not violations


def test_citation_flags_unknown_marker() -> None:
    citations, violations = CitationValidator().validate("Bad [cite:threat_score:ghost]", ())
    assert not citations
    assert violations and violations[0].reason == "unresolved_citation"


def test_citation_strip_markers() -> None:
    clean = CitationValidator.strip_markers("Text [cite:a:b] here")
    assert "[cite:" not in clean


# --- grounding validation ------------------------------------------------


def test_grounding_empty_context_is_insufficient() -> None:
    outcome = GroundingValidator().validate("anything", (), (), ())
    assert outcome.grounding_score == 0.0
    assert outcome.violations


def test_grounding_scores_citation_coverage() -> None:
    from core.domain.copilot import Citation

    items = (ContextItem(kind="k", source_id="1", label="l", summary="s"),)
    citations = (Citation(kind="k", source_id="1", label="l"),)
    outcome = GroundingValidator().validate("grounded", citations, (), items)
    assert outcome.grounding_score == 1.0


def test_grounding_strict_replaces_ungrounded_answer() -> None:
    items = (ContextItem(kind="k", source_id="1", label="l", summary="s"),)
    outcome = GroundingValidator(strict=True).validate("ungrounded", (), (), items)
    assert "does not currently hold enough" in outcome.answer
    assert outcome.grounding_score == 0.0


# --- session manager -----------------------------------------------------


def test_session_append_and_get() -> None:
    from core.domain.copilot import ConversationTurn

    sessions = SessionManager()
    session = sessions.get_or_create("")
    updated = sessions.append_turn(session.session_id, ConversationTurn(question="q", answer="a"))
    assert len(updated.turns) == 1
    assert sessions.get(session.session_id) is not None


def test_session_lru_eviction() -> None:
    sessions = SessionManager(max_sessions=2)
    sessions.get_or_create("a")
    sessions.get_or_create("b")
    sessions.get_or_create("c")
    assert sessions.get("a") is None
    assert sessions.metrics()["evictions"] == 1.0


def test_session_turn_bound() -> None:
    from core.domain.copilot import ConversationTurn

    sessions = SessionManager(max_turns=2)
    sessions.get_or_create("s")
    for index in range(4):
        sessions.append_turn("s", ConversationTurn(question=f"q{index}", answer="a"))
    session = sessions.get("s")
    assert session is not None
    assert len(session.turns) == 2


def test_session_close() -> None:
    sessions = SessionManager()
    sessions.get_or_create("x")
    assert sessions.close("x") is True
    assert sessions.close("x") is False


# --- orchestrator end to end ---------------------------------------------


def test_orchestrator_grounded_answer() -> None:
    orch = _orchestrator(_FakeProvider())
    response = orch.ask(CopilotQuery(question="why is url-1 malicious?", artifact_id="url-1"))
    assert response.available
    assert response.is_grounded
    assert response.citations
    assert response.prompt_metadata.skill_id == "threat_investigation"
    assert response.session_id


def test_orchestrator_provider_unavailable_degrades() -> None:
    orch = _orchestrator(_FakeProvider(available=False))
    response = orch.ask(CopilotQuery(question="status?"))
    assert response.available is False
    assert "not available" in response.answer


def test_orchestrator_records_turn() -> None:
    orch = _orchestrator(_FakeProvider())
    first = orch.ask(CopilotQuery(question="why is url-1 malicious?", artifact_id="url-1"))
    orch.ask(
        CopilotQuery(question="and file-1?", session_id=first.session_id, artifact_id="file-1")
    )
    session = orch._sessions.get(first.session_id)
    assert session is not None
    assert len(session.turns) == 2


def test_orchestrator_marker_stripped_from_answer() -> None:
    orch = _orchestrator(_FakeProvider())
    response = orch.ask(CopilotQuery(question="why is url-1 malicious?", artifact_id="url-1"))
    assert "[cite:" not in response.answer


def test_orchestrator_empty_context_says_insufficient() -> None:
    # A query with focus on a non-existent artifact yields global context; use a
    # provider that returns no citation to exercise the no-citation path.
    orch = _orchestrator(_FakeProvider(text="I cannot find that."))
    response = orch.ask(CopilotQuery(question="explain ghost", artifact_id="ghost"))
    assert response.available


@pytest.mark.parametrize(
    "question,expected",
    [
        ("Explain this indicator", IntentKind.IOC_INTELLIGENCE),
        ("Show the attack chain", IntentKind.INCIDENT_ANALYSIS),
        ("What is connected to this node?", IntentKind.GRAPH_REASONING),
        ("Give me an executive overview", IntentKind.EXECUTIVE_SUMMARY),
        ("Why is this phishing?", IntentKind.THREAT_INVESTIGATION),
    ],
)
def test_intent_matrix(question: str, expected: IntentKind) -> None:
    intent = IntentDetector().detect(CopilotQuery(question=question), FocusState())
    assert intent.intent is expected

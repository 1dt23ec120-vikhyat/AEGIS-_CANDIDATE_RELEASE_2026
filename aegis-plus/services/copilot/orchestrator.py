"""Copilot orchestrator (M12 Phase 1).

The single entry point that sequences the reasoning pipeline:

    question -> intent detection -> skill selection -> context collection
             -> prompt building -> LLM provider -> citation validation
             -> grounding validation -> response formatting -> response

The orchestrator owns only the sequence. Each stage is a discrete collaborator
that can be tested in isolation, and the orchestrator holds no intelligence logic
of its own. It records per-run observability through :class:`MeteredService`.

The Copilot never mutates platform state and never invokes a detection engine; it
consumes the read-only context the collector gathered and returns a grounded,
cited answer — degrading gracefully to an explicit "unavailable" response when
the LLM provider cannot be reached.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from core.domain.copilot import (
    ConversationTurn,
    CopilotContext,
    CopilotQuery,
    CopilotResponse,
    CopilotStreamEvent,
    PromptMetadata,
)
from core.domain.copilot_session import FocusState
from core.interfaces import ILogger
from core.interfaces.llm_provider import ILLMProvider, LLMRequest, LLMResult
from services.analytics.observability import MeteredService, tracked
from services.copilot.citations import CitationValidator
from services.copilot.context import ContextCollector
from services.copilot.formatter import ResponseFormatter
from services.copilot.grounding import GroundingValidator
from services.copilot.intent import IntentDetector
from services.copilot.prompt import BuiltPrompt, PromptBuilder
from services.copilot.session import SessionManager
from services.copilot.skills import SkillRegistry

_UNAVAILABLE_MESSAGE = (
    "The AI Security Copilot is not available right now (the language model "
    "provider is not configured or could not be reached). The platform's "
    "deterministic intelligence remains fully available in the dashboards."
)


@dataclass(frozen=True, slots=True)
class _PreparedTurn:
    """The read-only pipeline preparation shared by streaming and non-streaming."""

    question: str
    session_id: str
    intent_value: str
    context: CopilotContext
    prompt: BuiltPrompt


class CopilotOrchestrator(MeteredService):
    """Sequences the read-only Copilot reasoning pipeline."""

    def __init__(  # noqa: PLR0913 - one collaborator per pipeline stage
        self,
        intent_detector: IntentDetector,
        skill_registry: SkillRegistry,
        collector: ContextCollector,
        prompt_builder: PromptBuilder,
        provider: ILLMProvider,
        citation_validator: CitationValidator,
        grounding_validator: GroundingValidator,
        formatter: ResponseFormatter,
        sessions: SessionManager,
        logger: ILogger,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.1,
    ) -> None:
        """Initialize the orchestrator with the pipeline collaborators."""
        super().__init__()
        self._intent = intent_detector
        self._skills = skill_registry
        self._collector = collector
        self._builder = prompt_builder
        self._provider = provider
        self._citations = citation_validator
        self._grounding = grounding_validator
        self._formatter = formatter
        self._sessions = sessions
        self._logger = logger
        self._max_tokens = max_tokens
        self._temperature = temperature

    @tracked
    def ask(self, query: CopilotQuery) -> CopilotResponse:
        """Answer a query through the full read-only pipeline (non-streaming)."""
        prep = self._prepare(query)

        # [5] LLM provider — graceful degradation on any failure.
        if not self._provider.is_available():
            self._logger.warning("copilot: provider unavailable")
            return self._formatter.unavailable(
                _UNAVAILABLE_MESSAGE, prep.prompt.metadata, prep.session_id
            )

        result = self._provider.complete(
            LLMRequest(
                system_prompt=prep.prompt.system_prompt,
                user_message=prep.prompt.user_message,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )
        )
        if not result.success:
            self._logger.warning("copilot: provider error: %s", result.error)
            return self._formatter.unavailable(
                _UNAVAILABLE_MESSAGE, prep.prompt.metadata, prep.session_id
            )

        return self._finalize(prep, result.text, result)

    def stream_ask(self, query: CopilotQuery) -> Iterator[CopilotStreamEvent]:
        """Answer a query with progressive streaming.

        Yields ``token`` events carrying raw incremental text for UI
        responsiveness, then a terminal ``final`` event whose ``response`` is the
        *grounding-validated* answer — grounding and citation validation run on
        the complete text exactly as in :meth:`ask`, so streaming never weakens
        the guarantees of ADR-0002. Any provider or stream failure yields an
        ``error`` event with a graceful fallback response; callers that cannot
        stream should use :meth:`ask` instead.
        """
        prep = self._prepare(query)

        if not self._provider.is_available() or not self._provider.supports_streaming():
            response = self._formatter.unavailable(
                _UNAVAILABLE_MESSAGE, prep.prompt.metadata, prep.session_id
            )
            yield CopilotStreamEvent(kind="error", error="streaming unavailable", response=response)
            return

        chunks: list[str] = []
        prompt_tokens = 0
        completion_tokens = 0
        latency_ms = 0.0
        for chunk in self._provider.stream(
            LLMRequest(
                system_prompt=prep.prompt.system_prompt,
                user_message=prep.prompt.user_message,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )
        ):
            if chunk.text:
                chunks.append(chunk.text)
                yield CopilotStreamEvent(kind="token", text=chunk.text)
            if chunk.done:
                if not chunk.success:
                    self._logger.warning("copilot: stream error: %s", chunk.error)
                    response = self._formatter.unavailable(
                        _UNAVAILABLE_MESSAGE, prep.prompt.metadata, prep.session_id
                    )
                    yield CopilotStreamEvent(kind="error", error=chunk.error, response=response)
                    return
                prompt_tokens = chunk.prompt_tokens
                completion_tokens = chunk.completion_tokens
                latency_ms = chunk.latency_ms

        raw_text = "".join(chunks)
        result = LLMResult(
            text=raw_text,
            model_id=self._provider.model_id(),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            success=True,
        )
        response = self._finalize(prep, raw_text, result)
        yield CopilotStreamEvent(kind="final", response=response)

    # --- shared pipeline stages -----------------------------------------

    def _prepare(self, query: CopilotQuery) -> _PreparedTurn:
        """Run stages [1]-[4]: intent, skill, context, prompt (read-only)."""
        session = self._sessions.get_or_create(query.session_id)
        focus = self._merge_focus(query, session.focus)
        intent = self._intent.detect(query, focus)
        skill = self._skills.for_intent(intent.intent)
        spec = skill.spec()
        context = self._collector.collect(intent, spec, focus)
        prompt = self._builder.build(
            query,
            intent,
            spec,
            skill.system_fragment(),
            context,
            session.turns,
            model_id=self._provider.model_id(),
            provider=self._provider.provider_name(),
            temperature=self._temperature,
        )
        return _PreparedTurn(
            question=query.question,
            session_id=session.session_id,
            intent_value=intent.intent.value,
            context=context,
            prompt=prompt,
        )

    def _finalize(self, prep: _PreparedTurn, raw_text: str, result: LLMResult) -> CopilotResponse:
        """Run stages [6]-[8]: citation + grounding validation, format, record."""
        citations, citation_violations = self._citations.validate(raw_text, prep.context.items)
        clean_answer = self._citations.strip_markers(raw_text)
        outcome = self._grounding.validate(
            clean_answer, citations, citation_violations, prep.context.items
        )
        response = self._formatter.format(
            outcome, prep.context, prep.prompt.metadata, result, prep.session_id
        )
        self._sessions.append_turn(
            prep.session_id,
            ConversationTurn(
                question=prep.question,
                answer=response.answer,
                intent=prep.intent_value,
                timestamp=prep.prompt.metadata.timestamp,
            ),
        )
        return response

    def update_focus(self, session_id: str, focus: FocusState) -> None:
        """Update the analyst focus for a session (called by the UI)."""
        self._sessions.update_focus(session_id, focus)

    def _merge_focus(self, query: CopilotQuery, focus: FocusState) -> FocusState:
        """Overlay explicit query hints on top of the session focus."""
        return FocusState(
            current_artifact_id=query.artifact_id or focus.current_artifact_id,
            current_incident_id=query.incident_id or focus.current_incident_id,
            active_campaign_id=query.campaign_id or focus.active_campaign_id,
            recent_graph_selections=focus.recent_graph_selections,
        )

    @staticmethod
    def unavailable_metadata() -> PromptMetadata:
        """Return empty provenance for a pre-pipeline unavailability."""
        return PromptMetadata()

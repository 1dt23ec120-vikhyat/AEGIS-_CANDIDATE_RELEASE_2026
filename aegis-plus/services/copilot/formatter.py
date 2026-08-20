"""Copilot response formatter (M12 Phase 1).

Assembles the final :class:`CopilotResponse` from the validated grounding
outcome, the prompt provenance, the LLM diagnostics, and the context that was
consulted. The formatter surfaces related intelligence references — the context
items that were provided but not directly cited — so the analyst can see what
else the platform knows that is adjacent to the answer.
"""

from __future__ import annotations

from core.domain.copilot import (
    ContextItem,
    CopilotContext,
    CopilotResponse,
    PromptMetadata,
)
from core.interfaces.llm_provider import LLMResult
from services.copilot.grounding import GroundingOutcome

_MAX_RELATED = 5


class ResponseFormatter:
    """Builds the final, clean Copilot response."""

    def format(
        self,
        outcome: GroundingOutcome,
        context: CopilotContext,
        metadata: PromptMetadata,
        result: LLMResult,
        session_id: str,
    ) -> CopilotResponse:
        """Assemble the final response."""
        cited_keys = {c.citation_key for c in outcome.citations}
        related = tuple(item for item in context.items if item.citation_key not in cited_keys)[
            :_MAX_RELATED
        ]

        return CopilotResponse(
            answer=outcome.answer,
            citations=outcome.citations,
            related=related,
            context_summary=self._summary(context.items),
            grounding_score=outcome.grounding_score,
            grounding_violations=outcome.violations,
            prompt_metadata=metadata,
            session_id=session_id,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
            latency_ms=result.latency_ms,
            available=True,
        )

    def unavailable(
        self, message: str, metadata: PromptMetadata, session_id: str
    ) -> CopilotResponse:
        """Build a graceful response for when the provider is unavailable."""
        return CopilotResponse(
            answer=message,
            prompt_metadata=metadata,
            session_id=session_id,
            grounding_score=0.0,
            available=False,
        )

    def _summary(self, items: tuple[ContextItem, ...]) -> tuple[str, ...]:
        return tuple(f"{item.kind}: {item.label}" for item in items)

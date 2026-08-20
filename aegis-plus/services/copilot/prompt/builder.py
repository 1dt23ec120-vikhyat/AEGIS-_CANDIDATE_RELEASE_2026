"""Copilot prompt builder (M12 Phase 1).

Assembles the system prompt (scaffold + skill fragment + rendered context +
conversation history) and the user message, and records the full prompt
provenance in a :class:`PromptMetadata`. The builder performs no I/O and no
intelligence work — it is a deterministic string assembler.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.domain.copilot import (
    ContextItem,
    ConversationTurn,
    CopilotContext,
    CopilotQuery,
    DetectedIntent,
    PromptMetadata,
)
from core.interfaces.copilot_skill import SkillSpec
from services.copilot.prompt import templates

_CHARS_PER_TOKEN = 4


class BuiltPrompt:
    """The assembled prompt plus its provenance metadata."""

    def __init__(self, system_prompt: str, user_message: str, metadata: PromptMetadata) -> None:
        """Initialize the built prompt."""
        self.system_prompt = system_prompt
        self.user_message = user_message
        self.metadata = metadata


class PromptBuilder:
    """Assembles the grounded system prompt and records its provenance."""

    def __init__(self, *, history_turns: int = 4) -> None:
        """Initialize the builder.

        Args:
            history_turns: How many prior conversation turns to include.
        """
        self._history_turns = history_turns

    def build(
        self,
        query: CopilotQuery,
        intent: DetectedIntent,
        spec: SkillSpec,
        skill_fragment: str,
        context: CopilotContext,
        history: tuple[ConversationTurn, ...],
        *,
        model_id: str,
        provider: str,
        temperature: float,
    ) -> BuiltPrompt:
        """Assemble the system prompt, user message, and prompt metadata."""
        sections: list[str] = [
            templates.SYSTEM_SCAFFOLD,
            "SKILL GUIDANCE\n" + skill_fragment,
            templates.render_context_block(context.items),
        ]
        history_block = self._render_history(history)
        if history_block:
            sections.append(history_block)

        system_prompt = "\n\n".join(sections)
        user_message = query.question

        metadata = PromptMetadata(
            prompt_id=templates.SYSTEM_PROMPT_ID,
            prompt_version=templates.SYSTEM_PROMPT_VERSION,
            skill_id=spec.skill_id,
            intent=intent.intent.value,
            model_id=model_id,
            provider=provider,
            temperature=temperature,
            timestamp=datetime.now(UTC).isoformat(),
            context_item_count=len(context.items),
            prompt_token_estimate=self._estimate_tokens(system_prompt, user_message),
        )
        return BuiltPrompt(system_prompt, user_message, metadata)

    def _render_history(self, history: tuple[ConversationTurn, ...]) -> str:
        if not history or self._history_turns <= 0:
            return ""
        recent = history[-self._history_turns :]
        lines = ["CONVERSATION HISTORY"]
        for turn in recent:
            lines.append(f"Q: {turn.question}")
            lines.append(f"A: {turn.answer}")
        return "\n".join(lines)

    def _estimate_tokens(self, *parts: str) -> int:
        total = sum(len(part) for part in parts)
        return max(1, total // _CHARS_PER_TOKEN)

    @staticmethod
    def context_labels(items: tuple[ContextItem, ...]) -> tuple[str, ...]:
        """Produce a short human-readable summary of the context consulted."""
        return tuple(f"{item.kind}: {item.label}" for item in items)

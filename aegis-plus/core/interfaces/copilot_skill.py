"""Copilot skill port (M12 Phase 1).

A skill is a small, focused unit of Copilot behaviour: it declares which intent
it serves, contributes a skill-specific fragment to the system prompt, and names
the intelligence scope it needs. Skills are registered with the orchestrator's
registry; adding a new skill is registration only — the pipeline, orchestrator,
and context collector are untouched.

Skills contain *no* intelligence logic. They describe *what* context to gather
(by scope) and *how* to frame the answer (by prompt fragment); the collector and
the existing platform services do the actual work.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from core.domain.copilot import IntentKind


@dataclass(frozen=True, slots=True)
class SkillSpec:
    """Static description of a skill.

    ``context_scope`` selects the collection strategy the context collector runs
    (``"artifact"``, ``"incident"``, ``"campaign"``, ``"global"``). ``prompt_id``
    and ``prompt_version`` give the skill's prompt fragment stable provenance.
    """

    skill_id: str
    name: str
    intent: IntentKind
    context_scope: str
    prompt_id: str
    prompt_version: str


class ICopilotSkill(ABC):
    """Contract every Copilot skill implements."""

    @abstractmethod
    def spec(self) -> SkillSpec:
        """Return the skill's static description."""

    @abstractmethod
    def system_fragment(self) -> str:
        """Return the skill-specific guidance added to the system prompt."""

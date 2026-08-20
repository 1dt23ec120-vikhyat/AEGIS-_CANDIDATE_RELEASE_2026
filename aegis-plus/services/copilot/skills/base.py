"""Base Copilot skill (M12 Phase 1).

A tiny concrete base that stores a :class:`SkillSpec` and a prompt fragment, so
each concrete skill is a few lines declaring its identity, intent, context scope,
and framing guidance. Skills carry no intelligence logic — they only declare
*what* context to gather (by scope) and *how* to frame the answer.
"""

from __future__ import annotations

from core.interfaces.copilot_skill import ICopilotSkill, SkillSpec


class BaseSkill(ICopilotSkill):
    """Concrete base storing a spec and a system-prompt fragment."""

    def __init__(self, spec: SkillSpec, fragment: str) -> None:
        """Initialize the skill.

        Args:
            spec: The skill's static description.
            fragment: The skill-specific system-prompt guidance.
        """
        self._spec = spec
        self._fragment = fragment

    def spec(self) -> SkillSpec:
        """Return the skill's static description."""
        return self._spec

    def system_fragment(self) -> str:
        """Return the skill-specific guidance added to the system prompt."""
        return self._fragment

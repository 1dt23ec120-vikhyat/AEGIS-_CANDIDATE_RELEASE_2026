"""Copilot skill definitions and registry (M12 Phase 1).

Five focused skills covering the first release: Threat Investigation, IOC
Intelligence, Graph Reasoning, Incident Analysis, and Executive Summary. Each
declares the intent it serves, the context scope the collector should run, and a
prompt fragment that frames the answer.

The :class:`SkillRegistry` maps a detected intent to a skill. Adding a new skill
is registration only — the orchestrator, pipeline, and collector are untouched.
"""

from __future__ import annotations

from core.domain.copilot import IntentKind
from core.interfaces.copilot_skill import ICopilotSkill, SkillSpec
from services.copilot.skills.base import BaseSkill

_THREAT_INVESTIGATION = BaseSkill(
    SkillSpec(
        skill_id="threat_investigation",
        name="Threat Investigation",
        intent=IntentKind.THREAT_INVESTIGATION,
        context_scope="artifact",
        prompt_id="skill.threat_investigation",
        prompt_version="1.0.0",
    ),
    "You are explaining why an artifact received its deterministic verdict and "
    "risk score. Ground every statement about severity, confidence, exposure, "
    "and category in the provided threat score and evidence. Do not invent a new "
    "verdict or adjust the platform's score — explain the score that already "
    "exists, and cite the threat_score and ioc_intelligence context.",
)

_IOC_INTELLIGENCE = BaseSkill(
    SkillSpec(
        skill_id="ioc_intelligence",
        name="IOC Intelligence",
        intent=IntentKind.IOC_INTELLIGENCE,
        context_scope="artifact",
        prompt_id="skill.ioc_intelligence",
        prompt_version="1.0.0",
    ),
    "You are explaining indicators of compromise: their frequency, prevalence, "
    "reuse, confidence, and aging. Use only the ioc_intelligence context. When an "
    "IOC is reused across artifacts, explain the reuse using the provided figures "
    "and cite each ioc_intelligence source.",
)

_GRAPH_REASONING = BaseSkill(
    SkillSpec(
        skill_id="graph_reasoning",
        name="Graph Reasoning",
        intent=IntentKind.GRAPH_REASONING,
        context_scope="artifact",
        prompt_id="skill.graph_reasoning",
        prompt_version="1.0.0",
    ),
    "You are explaining relationships in the knowledge graph: neighbourhood, "
    "blast radius, centrality, and shared infrastructure. Use only the graph and "
    "analytics context (blast_radius, neighbourhood, central_node). Describe what "
    "connects to what and how far intelligence can spread, citing each source. Do "
    "not assert relationships that are not present in the context.",
)

_INCIDENT_ANALYSIS = BaseSkill(
    SkillSpec(
        skill_id="incident_analysis",
        name="Incident Analysis",
        intent=IntentKind.INCIDENT_ANALYSIS,
        context_scope="incident",
        prompt_id="skill.incident_analysis",
        prompt_version="1.0.0",
    ),
    "You are analysing an incident: its root cause, the attack chain, and the "
    "affected artifacts with their scores. Use only the root_cause, attack_chain, "
    "and threat_score context. Present the incident clearly for a responding "
    "analyst and cite each source. Never fabricate a root cause or chain step "
    "that is not in the context.",
)

_EXECUTIVE_SUMMARY = BaseSkill(
    SkillSpec(
        skill_id="executive_summary",
        name="Executive Summary",
        intent=IntentKind.EXECUTIVE_SUMMARY,
        context_scope="global",
        prompt_id="skill.executive_summary",
        prompt_version="1.0.0",
    ),
    "You are producing a concise executive summary of the current security "
    "posture from the platform's top threats, campaigns, IOCs, and "
    "recommendations. Use only the provided context. Lead with the most severe "
    "items, keep the language accessible, and cite each figure you quote. Do not "
    "introduce threats, campaigns, or recommendations that are not in the "
    "context.",
)


class SkillRegistry:
    """Maps a detected intent to a registered skill."""

    def __init__(self, skills: tuple[ICopilotSkill, ...]) -> None:
        """Initialize the registry from a set of skills.

        Args:
            skills: The skills to register. The last skill registered for an
                intent wins, matching typical override semantics.
        """
        self._by_intent: dict[IntentKind, ICopilotSkill] = {}
        self._by_id: dict[str, ICopilotSkill] = {}
        for skill in skills:
            spec = skill.spec()
            self._by_intent[spec.intent] = skill
            self._by_id[spec.skill_id] = skill

    def for_intent(self, intent: IntentKind) -> ICopilotSkill:
        """Return the skill serving the given intent.

        Falls back to the Executive Summary skill if no skill is registered for
        the intent, so the pipeline always has a skill to run.
        """
        skill = self._by_intent.get(intent)
        if skill is not None:
            return skill
        return self._by_intent.get(IntentKind.EXECUTIVE_SUMMARY, _EXECUTIVE_SUMMARY)

    def skill_ids(self) -> tuple[str, ...]:
        """Return the registered skill ids (sorted, for diagnostics)."""
        return tuple(sorted(self._by_id))


def default_skills() -> tuple[ICopilotSkill, ...]:
    """Return the five first-release skills."""
    return (
        _THREAT_INVESTIGATION,
        _IOC_INTELLIGENCE,
        _GRAPH_REASONING,
        _INCIDENT_ANALYSIS,
        _EXECUTIVE_SUMMARY,
    )


def build_default_registry() -> SkillRegistry:
    """Build a registry populated with the first-release skills."""
    return SkillRegistry(default_skills())

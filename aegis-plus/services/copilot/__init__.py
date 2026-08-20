"""AI Security Copilot services (M12).

A read-only intelligence consumer built over the existing platform. The Copilot
explains and reasons over the deterministic intelligence the platform produces
and is never itself a source of truth (ADR-0002). Every stage of its pipeline is
a discrete, testable component; the orchestrator only sequences them.
"""

from services.copilot.citations import CitationValidator
from services.copilot.context import ContextCollector
from services.copilot.formatter import ResponseFormatter
from services.copilot.grounding import GroundingValidator
from services.copilot.intent import IntentDetector
from services.copilot.orchestrator import CopilotOrchestrator
from services.copilot.prompt import PromptBuilder
from services.copilot.session import SessionManager
from services.copilot.skills import SkillRegistry, build_default_registry, default_skills

__all__ = [
    "CitationValidator",
    "ContextCollector",
    "CopilotOrchestrator",
    "GroundingValidator",
    "IntentDetector",
    "PromptBuilder",
    "ResponseFormatter",
    "SessionManager",
    "SkillRegistry",
    "build_default_registry",
    "default_skills",
]

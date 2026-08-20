"""AI Security Copilot domain model (M12 Phase 1).

Immutable, framework-free value objects for the read-only AI Security Copilot.
The Copilot is an *intelligence consumer*: it explains and reasons over the
deterministic intelligence the platform already produces, and is never itself a
source of truth (see ADR-0002). Every type here is a plain, frozen dataclass —
no I/O, no state, no framework dependency — so it satisfies the Core Domain
Purity contract.

The vocabulary:

- :class:`IntentKind` / :class:`DetectedIntent` — the deterministic intent the
  analyst's question maps to, which selects a skill.
- :class:`CopilotQuery` — an analyst question plus optional focus and session.
- :class:`ContextItem` — one serialized piece of platform intelligence that the
  collector gathered for the answer.
- :class:`Citation` — a link from a claim in the answer back to a platform
  source (grounding, made visible).
- :class:`PromptMetadata` — the full provenance of the prompt that produced the
  answer, for evaluation and future tuning.
- :class:`CopilotResponse` — the grounded answer with citations, related
  intelligence references, and provenance.
- :class:`ConversationTurn` — one question/answer pair, held in memory only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IntentKind(str, Enum):
    """The deterministic intent an analyst question maps to.

    Intent is inferred by simple, explainable keyword and focus rules — never by
    the LLM — and it drives skill selection. New intents are additive.
    """

    THREAT_INVESTIGATION = "threat_investigation"
    IOC_INTELLIGENCE = "ioc_intelligence"
    GRAPH_REASONING = "graph_reasoning"
    INCIDENT_ANALYSIS = "incident_analysis"
    EXECUTIVE_SUMMARY = "executive_summary"


@dataclass(frozen=True, slots=True)
class DetectedIntent:
    """The result of deterministic intent detection.

    ``confidence`` is a transparency signal in ``[0, 1]`` describing how strongly
    the rules matched; ``rationale`` explains *why* this intent was chosen, and
    ``focus_id``/``focus_type`` capture any concrete platform entity the question
    is about (an artifact, incident, or campaign).
    """

    intent: IntentKind
    confidence: float = 0.0
    focus_id: str = ""
    focus_type: str = ""
    matched_terms: tuple[str, ...] = ()
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class CopilotQuery:
    """An analyst's question for the Copilot.

    ``session_id`` links the question to an in-memory conversation. ``artifact_id``
    / ``incident_id`` / ``campaign_id`` are optional focus hints supplied by the
    UI (for example, the artifact currently under investigation).
    """

    question: str
    session_id: str = ""
    artifact_id: str = ""
    incident_id: str = ""
    campaign_id: str = ""


@dataclass(frozen=True, slots=True)
class ContextItem:
    """One piece of platform intelligence included in the answer's context.

    ``kind`` names the intelligence source (``"threat_score"``,
    ``"ioc_intelligence"``, ``"attack_chain"``, …); ``source_id`` is the stable
    identifier the answer cites; ``summary`` is a deterministic natural-language
    rendering of the underlying DTO (never an LLM summary); and ``severity`` is
    the ranking weight used to order context under the token budget.
    """

    kind: str
    source_id: str
    label: str
    summary: str
    severity: float = 0.0
    token_estimate: int = 0

    @property
    def citation_key(self) -> str:
        """The ``kind:source_id`` key the LLM is instructed to cite."""
        return f"{self.kind}:{self.source_id}"


@dataclass(frozen=True, slots=True)
class CopilotContext:
    """The ranked, budget-bounded context assembled for a single query."""

    items: tuple[ContextItem, ...] = ()
    scope: str = ""
    total_token_estimate: int = 0
    truncated: bool = False
    collection_ms: float = 0.0

    @property
    def is_empty(self) -> bool:
        """Whether no platform intelligence was found for the question."""
        return not self.items


@dataclass(frozen=True, slots=True)
class Citation:
    """A resolved link from a claim in the answer to a platform source."""

    kind: str
    source_id: str
    label: str
    excerpt: str = ""

    @property
    def citation_key(self) -> str:
        """The ``kind:source_id`` key that appeared in the model output."""
        return f"{self.kind}:{self.source_id}"


@dataclass(frozen=True, slots=True)
class GroundingViolation:
    """A claim or citation that could not be grounded in the context."""

    reason: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PromptMetadata:
    """Full provenance of the prompt that produced a response.

    Accompanies every response so answers can be evaluated and prompts tuned
    later without any schema change.
    """

    prompt_id: str = ""
    prompt_version: str = ""
    skill_id: str = ""
    intent: str = ""
    model_id: str = ""
    provider: str = ""
    temperature: float = 0.0
    timestamp: str = ""
    context_item_count: int = 0
    prompt_token_estimate: int = 0


@dataclass(frozen=True, slots=True)
class CopilotResponse:
    """The Copilot's grounded answer to a single query.

    The answer is accompanied by the citations that ground it, references to the
    related intelligence that was consulted, a grounding score, and the prompt
    provenance. ``available`` is ``False`` when the LLM provider could not be
    reached — the platform stays fully operational and the Copilot degrades
    gracefully rather than raising.
    """

    answer: str
    citations: tuple[Citation, ...] = ()
    related: tuple[ContextItem, ...] = ()
    context_summary: tuple[str, ...] = ()
    grounding_score: float = 1.0
    grounding_violations: tuple[GroundingViolation, ...] = ()
    prompt_metadata: PromptMetadata = field(default_factory=PromptMetadata)
    session_id: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    available: bool = True

    @property
    def is_grounded(self) -> bool:
        """Whether the answer carried at least one resolved citation."""
        return bool(self.citations)


@dataclass(frozen=True, slots=True)
class ConversationTurn:
    """One question/answer pair in an in-memory conversation session."""

    question: str
    answer: str
    intent: str = ""
    timestamp: str = ""


@dataclass(frozen=True, slots=True)
class CopilotStreamEvent:
    """One event in a streamed Copilot answer.

    ``kind`` is ``"token"`` for an incremental delta (``text`` set), ``"final"``
    for the terminal event carrying the fully validated ``response``, or
    ``"error"`` for a stream failure (``error`` set, plus a graceful ``response``).
    Token events deliver *raw* model text for responsiveness; the authoritative,
    grounding-validated answer is always the one on the ``final`` event.
    """

    kind: str
    text: str = ""
    response: CopilotResponse | None = None
    error: str = ""

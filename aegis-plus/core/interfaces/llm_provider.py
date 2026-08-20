"""LLM provider port (M12 Phase 1).

The Core-owned, provider-agnostic contract for large-language-model inference.
The Copilot orchestrator depends only on this interface; concrete providers
(Claude in Phase 1, and OpenAI/Gemini/Ollama/LM Studio later) live in the ``ai``
layer and are selected at the composition root. Swapping providers is a wiring
change, never a change to the orchestrator or the pipeline.

The interface exposes a synchronous ``complete`` used by Phase 1 and a
``supports_streaming`` capability flag that reserves a streaming seam for Phase 2
without committing to an implementation now.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LLMStreamChunk:
    """One incremental chunk of a streamed completion.

    ``text`` is the delta to append to the answer so far. ``done`` marks the
    final chunk; when the stream failed, ``done`` is ``True`` with ``success``
    ``False`` and a populated ``error``. The terminal chunk also carries the
    token counts and latency for provenance, mirroring :class:`LLMResult`.
    """

    text: str = ""
    done: bool = False
    success: bool = True
    error: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class LLMRequest:
    """A single, self-contained inference request.

    The request carries everything the provider needs; there is no hidden state.
    ``system_prompt`` establishes the grounding rules and context, and
    ``user_message`` is the analyst's question.
    """

    system_prompt: str
    user_message: str
    max_tokens: int = 1024
    temperature: float = 0.1


@dataclass(frozen=True, slots=True)
class LLMResult:
    """The raw provider response, before grounding and citation validation.

    ``success`` is ``False`` on any provider error (missing credentials,
    timeout, transport failure, malformed response); ``error`` then carries a
    short diagnostic. Callers must handle the unsuccessful case gracefully — the
    Copilot never raises to the API on a provider failure.
    """

    text: str = ""
    model_id: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    success: bool = True
    error: str = ""


class ILLMProvider(ABC):
    """Provider-agnostic large-language-model inference contract."""

    @abstractmethod
    def complete(self, request: LLMRequest) -> LLMResult:
        """Run a single completion and return the raw result.

        Implementations must never raise for an expected provider failure;
        instead they return an :class:`LLMResult` with ``success=False`` and a
        populated ``error`` so the Copilot can degrade gracefully.
        """

    @abstractmethod
    def model_id(self) -> str:
        """Return the identifier of the active model (for provenance)."""

    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider's stable name (``"claude"``, ``"openai"``, …)."""

    @abstractmethod
    def is_available(self) -> bool:
        """Whether the provider is configured and ready to serve requests."""

    def supports_streaming(self) -> bool:
        """Whether this provider can stream (streaming seam; default ``False``)."""
        return False

    def stream(self, request: LLMRequest) -> Iterator[LLMStreamChunk]:
        """Stream a completion as incremental chunks.

        This is an optional capability with a safe default: providers that do not
        override it (or that are unavailable) yield a single terminal chunk
        signalling that streaming is unsupported, so callers fall back to
        :meth:`complete` without special-casing. Overriding providers must never
        raise for an expected failure; they yield a terminal chunk with
        ``success=False`` instead.
        """
        yield LLMStreamChunk(done=True, success=False, error="streaming not supported")

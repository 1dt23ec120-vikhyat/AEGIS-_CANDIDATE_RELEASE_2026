"""Base LLM provider (M12 Phase 1).

Shared scaffolding for concrete providers: a configured, reusable httpx client,
consistent timing, and a uniform error-to-:class:`LLMResult` mapping. Concrete
providers implement only the request/response shape for their API, keeping the
provider-agnostic contract clean and making additional providers cheap to add.
"""

from __future__ import annotations

import time
from abc import abstractmethod
from collections.abc import Iterator

import httpx

from core.interfaces import ILogger
from core.interfaces.llm_provider import ILLMProvider, LLMRequest, LLMResult, LLMStreamChunk


class BaseLLMProvider(ILLMProvider):
    """Base for HTTP-backed LLM providers."""

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        base_url: str,
        timeout_seconds: float,
        logger: ILogger,
    ) -> None:
        """Initialize the base provider.

        Args:
            model: The model identifier to request.
            api_key: The API credential (empty means unavailable).
            base_url: The API base URL.
            timeout_seconds: Per-request timeout.
            logger: Injected logger.
        """
        self._model = model
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._logger = logger

    def model_id(self) -> str:
        """Return the active model identifier."""
        return self._model

    def is_available(self) -> bool:
        """Whether the provider has a credential and can serve requests."""
        return bool(self._api_key)

    def complete(self, request: LLMRequest) -> LLMResult:
        """Run a single completion, mapping any failure to an ``LLMResult``."""
        if not self.is_available():
            return LLMResult(
                model_id=self._model,
                success=False,
                error="provider not configured (missing API key)",
            )
        start = time.perf_counter()
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    self._endpoint(),
                    headers=self._headers(),
                    json=self._payload(request),
                )
            latency = (time.perf_counter() - start) * 1000
            if response.status_code != httpx.codes.OK:
                return LLMResult(
                    model_id=self._model,
                    latency_ms=round(latency, 3),
                    success=False,
                    error=f"provider HTTP {response.status_code}",
                )
            return self._parse(response.json(), round(latency, 3))
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            latency = (time.perf_counter() - start) * 1000
            self._logger.warning("copilot provider error: %s", exc)
            return LLMResult(
                model_id=self._model,
                latency_ms=round(latency, 3),
                success=False,
                error=str(exc),
            )

    def stream(self, request: LLMRequest) -> Iterator[LLMStreamChunk]:
        """Stream a completion via server-sent events.

        Yields incremental text chunks and a terminal chunk carrying token
        counts and latency. Any failure — missing credential, non-200 status,
        transport error, or malformed event — is surfaced as a terminal chunk
        with ``success=False`` rather than raised, so the caller can fall back to
        :meth:`complete` or present an analyst-friendly state.
        """
        if not self.is_available():
            yield LLMStreamChunk(
                done=True, success=False, error="provider not configured (missing API key)"
            )
            return
        start = time.perf_counter()
        payload = {**self._payload(request), "stream": True}
        try:
            with (
                httpx.Client(timeout=self._timeout) as client,
                client.stream(
                    "POST", self._endpoint(), headers=self._headers(), json=payload
                ) as response,
            ):
                if response.status_code != httpx.codes.OK:
                    response.close()
                    yield LLMStreamChunk(
                        done=True,
                        success=False,
                        error=f"provider HTTP {response.status_code}",
                    )
                    return
                completion_tokens = 0
                prompt_tokens = 0
                for line in response.iter_lines():
                    delta = self._parse_stream_line(line)
                    if delta is None:
                        continue
                    text, p_tokens, c_tokens = delta
                    prompt_tokens = p_tokens or prompt_tokens
                    completion_tokens = c_tokens or completion_tokens
                    if text:
                        yield LLMStreamChunk(text=text)
            latency = (time.perf_counter() - start) * 1000
            yield LLMStreamChunk(
                done=True,
                success=True,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                latency_ms=round(latency, 3),
            )
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            self._logger.warning("copilot provider stream error: %s", exc)
            yield LLMStreamChunk(done=True, success=False, error=str(exc))

    # --- provider-specific hooks ----------------------------------------

    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider's stable name."""

    @abstractmethod
    def _endpoint(self) -> str:
        """Return the full completion endpoint URL."""

    @abstractmethod
    def _headers(self) -> dict[str, str]:
        """Return the request headers (including auth)."""

    @abstractmethod
    def _payload(self, request: LLMRequest) -> dict[str, object]:
        """Return the JSON request body for a completion."""

    @abstractmethod
    def _parse(self, body: dict[str, object], latency_ms: float) -> LLMResult:
        """Map a successful provider response body to an ``LLMResult``."""

    @abstractmethod
    def _parse_stream_line(self, line: str) -> tuple[str, int, int] | None:
        """Parse one SSE line into ``(text_delta, prompt_tokens, completion_tokens)``.

        Returns ``None`` for lines that carry no delta (comments, event names,
        keep-alives, or the terminal marker). Token counts are ``0`` when not
        present on that line.
        """

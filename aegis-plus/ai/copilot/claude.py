"""Claude LLM provider (M12 Phase 1).

Implements :class:`ILLMProvider` against the Anthropic Messages API. This is the
primary provider for the first Copilot release; the provider-agnostic contract
means additional providers (OpenAI, Gemini, Ollama, LM Studio) can be added later
without any change to the orchestrator.

The provider degrades gracefully: with no API key it reports itself unavailable,
and any transport or parsing failure is returned as an unsuccessful
:class:`LLMResult` rather than raised — the platform stays operational.
"""

from __future__ import annotations

import json
from typing import Any, cast

from ai.copilot.base import BaseLLMProvider
from core.interfaces import ILogger
from core.interfaces.llm_provider import LLMRequest, LLMResult


class ClaudeProvider(BaseLLMProvider):
    """Anthropic Claude provider for the Copilot."""

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        base_url: str,
        anthropic_version: str,
        timeout_seconds: float,
        logger: ILogger,
    ) -> None:
        """Initialize the Claude provider.

        Args:
            model: The Claude model identifier.
            api_key: The Anthropic API key (empty means unavailable).
            base_url: The API base URL.
            anthropic_version: The Anthropic API version header value.
            timeout_seconds: Per-request timeout.
            logger: Injected logger.
        """
        super().__init__(
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            logger=logger,
        )
        self._anthropic_version = anthropic_version

    def provider_name(self) -> str:
        """Return the provider name."""
        return "claude"

    def supports_streaming(self) -> bool:
        """Claude supports server-sent-event streaming."""
        return True

    def _endpoint(self) -> str:
        return f"{self._base_url}/v1/messages"

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": self._anthropic_version,
            "content-type": "application/json",
        }

    def _payload(self, request: LLMRequest) -> dict[str, object]:
        return {
            "model": self._model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "system": request.system_prompt,
            "messages": [{"role": "user", "content": request.user_message}],
        }

    def _parse(self, body: dict[str, object], latency_ms: float) -> LLMResult:
        content = body.get("content", [])
        text_parts: list[str] = []
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_parts.append(str(block.get("text", "")))
        text = "".join(text_parts).strip()

        usage = body.get("usage", {})
        prompt_tokens = 0
        completion_tokens = 0
        if isinstance(usage, dict):
            prompt_tokens = int(cast(dict[str, Any], usage).get("input_tokens", 0) or 0)
            completion_tokens = int(cast(dict[str, Any], usage).get("output_tokens", 0) or 0)

        if not text:
            return LLMResult(
                model_id=self._model,
                latency_ms=latency_ms,
                success=False,
                error="empty completion",
            )
        return LLMResult(
            text=text,
            model_id=str(body.get("model", self._model)),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            success=True,
        )

    def _parse_stream_line(self, line: str) -> tuple[str, int, int] | None:
        """Parse one Anthropic SSE ``data:`` line into a text delta + usage.

        Anthropic streams a sequence of JSON events. Text deltas arrive as
        ``content_block_delta`` events with a ``text_delta``; input token usage
        appears on ``message_start`` and output token usage on ``message_delta``.
        Non-data lines, event-name lines, and unrecognized events yield ``None``.
        """
        event = self._decode_sse(line)
        if event is None:
            return None
        handler = _STREAM_HANDLERS.get(str(event.get("type", "")))
        return handler(event) if handler is not None else None

    @staticmethod
    def _decode_sse(line: str) -> dict[str, Any] | None:
        stripped = line.strip()
        if not stripped or not stripped.startswith("data:"):
            return None
        data = stripped[len("data:") :].strip()
        if not data or data == "[DONE]":
            return None
        try:
            event = json.loads(data)
        except ValueError:
            return None
        return event if isinstance(event, dict) else None


def _handle_content_delta(event: dict[str, Any]) -> tuple[str, int, int] | None:
    delta = event.get("delta")
    if isinstance(delta, dict) and delta.get("type") == "text_delta":
        return str(delta.get("text", "")), 0, 0
    return None


def _handle_message_start(event: dict[str, Any]) -> tuple[str, int, int]:
    message = event.get("message")
    usage = message.get("usage", {}) if isinstance(message, dict) else {}
    prompt_tokens = int(cast(dict[str, Any], usage).get("input_tokens", 0) or 0)
    return "", prompt_tokens, 0


def _handle_message_delta(event: dict[str, Any]) -> tuple[str, int, int]:
    usage = event.get("usage", {})
    completion_tokens = int(cast(dict[str, Any], usage).get("output_tokens", 0) or 0)
    return "", 0, completion_tokens


_STREAM_HANDLERS: dict[str, Any] = {
    "content_block_delta": _handle_content_delta,
    "message_start": _handle_message_start,
    "message_delta": _handle_message_delta,
}

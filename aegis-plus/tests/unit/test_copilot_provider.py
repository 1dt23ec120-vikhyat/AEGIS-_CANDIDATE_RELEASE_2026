"""Unit tests for the Copilot LLM provider layer (M12 Phase 1).

The provider is exercised without real network access by monkeypatching the
httpx client. These tests confirm graceful behaviour: an unconfigured provider
reports unavailable, a successful response parses text and token usage, and any
transport or HTTP error is mapped to an unsuccessful result rather than raised.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from ai.copilot import ClaudeProvider, build_provider
from config.schemas import CopilotSettings
from core.interfaces.llm_provider import LLMRequest


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
    def bind(self, **k: object) -> _FakeLogger:
        return self


def _provider(api_key: str) -> ClaudeProvider:
    return ClaudeProvider(
        model="claude-sonnet-4-6",
        api_key=api_key,
        base_url="https://api.anthropic.com",
        anthropic_version="2023-06-01",
        timeout_seconds=5.0,
        logger=_FakeLogger(),
    )


def test_provider_unavailable_without_key() -> None:
    provider = _provider("")
    assert provider.is_available() is False
    result = provider.complete(LLMRequest(system_prompt="s", user_message="u"))
    assert result.success is False
    assert "not configured" in result.error


def test_provider_parses_successful_response(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        status_code = httpx.codes.OK

        def json(self) -> dict[str, Any]:
            return {
                "model": "claude-sonnet-4-6",
                "content": [{"type": "text", "text": "Hello analyst."}],
                "usage": {"input_tokens": 12, "output_tokens": 4},
            }

    class _Client:
        def __init__(self, *a: object, **k: object) -> None: ...
        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *a: object) -> None: ...
        def post(self, *a: object, **k: object) -> _Response:
            return _Response()

    monkeypatch.setattr(httpx, "Client", _Client)
    provider = _provider("key-123")
    result = provider.complete(LLMRequest(system_prompt="s", user_message="u"))
    assert result.success is True
    assert result.text == "Hello analyst."
    assert result.prompt_tokens == 12
    assert result.completion_tokens == 4


def test_provider_maps_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        status_code = httpx.codes.INTERNAL_SERVER_ERROR

        def json(self) -> dict[str, Any]:
            return {}

    class _Client:
        def __init__(self, *a: object, **k: object) -> None: ...
        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *a: object) -> None: ...
        def post(self, *a: object, **k: object) -> _Response:
            return _Response()

    monkeypatch.setattr(httpx, "Client", _Client)
    result = _provider("key").complete(LLMRequest(system_prompt="s", user_message="u"))
    assert result.success is False
    assert "HTTP 500" in result.error


def test_provider_maps_transport_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Client:
        def __init__(self, *a: object, **k: object) -> None: ...
        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *a: object) -> None: ...
        def post(self, *a: object, **k: object) -> None:
            raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx, "Client", _Client)
    result = _provider("key").complete(LLMRequest(system_prompt="s", user_message="u"))
    assert result.success is False


def test_provider_empty_completion_is_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        status_code = httpx.codes.OK

        def json(self) -> dict[str, Any]:
            return {"content": [], "usage": {}}

    class _Client:
        def __init__(self, *a: object, **k: object) -> None: ...
        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *a: object) -> None: ...
        def post(self, *a: object, **k: object) -> _Response:
            return _Response()

    monkeypatch.setattr(httpx, "Client", _Client)
    result = _provider("key").complete(LLMRequest(system_prompt="s", user_message="u"))
    assert result.success is False
    assert "empty completion" in result.error


def test_factory_builds_claude(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    provider = build_provider(CopilotSettings(), _FakeLogger())
    assert provider.provider_name() == "claude"
    assert provider.is_available() is True


def test_factory_unknown_provider_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = build_provider(CopilotSettings(provider="gemini"), _FakeLogger())
    assert provider.provider_name() == "claude"
    assert provider.is_available() is False

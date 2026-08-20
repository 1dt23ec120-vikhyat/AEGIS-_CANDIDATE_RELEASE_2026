"""AI Copilot providers (M12 Phase 1).

Concrete :class:`ILLMProvider` implementations and a factory that selects one
from configuration. Phase 1 ships the Claude provider; the factory is the single
place a future provider (OpenAI, Gemini, Ollama, LM Studio) is registered, so the
orchestrator stays provider-agnostic.
"""

from __future__ import annotations

import os

from ai.copilot.base import BaseLLMProvider
from ai.copilot.claude import ClaudeProvider
from config.schemas import CopilotSettings
from core.interfaces import ILogger
from core.interfaces.llm_provider import ILLMProvider

__all__ = ["BaseLLMProvider", "ClaudeProvider", "build_provider"]


def build_provider(settings: CopilotSettings, logger: ILogger) -> ILLMProvider:
    """Build the configured LLM provider.

    The API key is read from the environment variable named in configuration, so
    no secret is ever stored in configuration files. An unknown provider name
    falls back to Claude with a warning; a missing key yields an unavailable
    provider that the Copilot degrades around gracefully.

    Args:
        settings: The Copilot configuration section.
        logger: Injected logger.

    Returns:
        A provider satisfying :class:`ILLMProvider`.
    """
    api_key = os.environ.get(settings.api_key_env, "")
    provider = settings.provider.lower()

    if provider != "claude":
        logger.warning(
            "copilot: provider %r not implemented in this phase; using claude",
            settings.provider,
        )

    return ClaudeProvider(
        model=settings.model,
        api_key=api_key,
        base_url=settings.api_base_url,
        anthropic_version=settings.anthropic_version,
        timeout_seconds=settings.request_timeout_seconds,
        logger=logger,
    )

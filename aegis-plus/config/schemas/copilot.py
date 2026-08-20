"""AI Security Copilot configuration schema (M12 Phase 1).

Holds the tunable configuration for the read-only AI Security Copilot: the LLM
provider selection and model, the API endpoint and credential environment
variable, generation limits, the context token budget, session capacity, and the
grounding mode. Keeping these in configuration (rather than hardcoding) follows
the established pattern for the AI subsystem and NFR §14.

The API key itself is never stored here — only the *name* of the environment
variable to read it from — so no secret lives in configuration files.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CopilotSettings(BaseModel):
    """AI Security Copilot configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = Field(default=True)
    provider: str = Field(default="claude", min_length=1)
    model: str = Field(default="claude-sonnet-4-6", min_length=1)
    api_base_url: str = Field(default="https://api.anthropic.com", min_length=1)
    api_key_env: str = Field(default="ANTHROPIC_API_KEY", min_length=1)
    anthropic_version: str = Field(default="2023-06-01", min_length=1)

    max_tokens: int = Field(default=1024, ge=64, le=8192)
    temperature: float = Field(default=0.1, ge=0.0, le=1.0)
    request_timeout_seconds: float = Field(default=30.0, gt=0.0)

    context_token_budget: int = Field(default=6000, ge=512, le=100000)
    max_context_items: int = Field(default=24, ge=1, le=200)

    max_sessions: int = Field(default=100, ge=1, le=10000)
    max_turns_per_session: int = Field(default=20, ge=1, le=200)
    history_turns_in_prompt: int = Field(default=4, ge=0, le=50)

    strict_grounding: bool = Field(default=False)

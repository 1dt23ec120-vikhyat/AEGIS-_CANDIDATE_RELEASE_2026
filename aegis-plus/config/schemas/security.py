"""Security configuration schema.

Secrets are modeled with :class:`~pydantic.SecretStr` so they are masked in
logs and representations. The secret value is supplied through the environment
(``AEGIS_SECRET_KEY``) and never persisted to a configuration file (NFR §7).

Per-field validation here is intentionally permissive so that development can
proceed with the insecure default; environment-aware enforcement (rejecting the
default and weak secrets in production) lives in ``config.validation``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from config import defaults


class SecuritySettings(BaseModel):
    """Security-related configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    secret_key: SecretStr = Field(default=SecretStr(defaults.INSECURE_SECRET_SENTINEL))
    session_timeout_minutes: int = Field(default=defaults.DEFAULT_SESSION_TIMEOUT_MINUTES, ge=1)

    @property
    def is_secret_configured(self) -> bool:
        """Whether a non-default secret key has been provided."""
        return self.secret_key.get_secret_value() != defaults.INSECURE_SECRET_SENTINEL

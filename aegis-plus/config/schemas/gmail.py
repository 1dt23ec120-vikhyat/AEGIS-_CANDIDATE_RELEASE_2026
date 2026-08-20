"""Gmail connector configuration schema (M14).

The Gmail connector is a read-only input source. Only the read-only Gmail scope
is permitted. No secret is stored in configuration: the OAuth client id is not a
secret, but the client secret is read from the environment variable named by
``client_secret_env`` (mirroring the Copilot API-key pattern), and user tokens are
stored in a protected local file outside the repository.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


class GmailSettings(BaseModel):
    """Gmail read-only connector configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = Field(default=True)

    # OAuth endpoints and API base (overridable for tests; defaults are Google's).
    auth_uri: str = Field(default="https://accounts.google.com/o/oauth2/v2/auth", min_length=1)
    token_uri: str = Field(default="https://oauth2.googleapis.com/token", min_length=1)
    api_base_url: str = Field(default="https://gmail.googleapis.com", min_length=1)

    # The OAuth client. The id is not secret; the secret comes from the env var
    # named here. Client id may be empty until the operator configures it.
    client_id: str = Field(default="")
    client_secret_env: str = Field(default="AEGIS_GMAIL_CLIENT_SECRET", min_length=1)

    # Strictly read-only. Enforced by the validator below.
    scope: str = Field(default=_READONLY_SCOPE, min_length=1)

    # Loopback callback: bound to 127.0.0.1 on an ephemeral port (port 0).
    loopback_host: str = Field(default="127.0.0.1", min_length=1)
    loopback_timeout_seconds: float = Field(default=180.0, gt=0.0, le=600.0)

    # Fetch limits (safety caps for a manual, analyst-triggered connector).
    default_query: str = Field(default="in:inbox", min_length=1)
    max_list_results: int = Field(default=25, ge=1, le=100)
    request_timeout_seconds: float = Field(default=30.0, gt=0.0)

    @field_validator("scope")
    @classmethod
    def _scope_must_be_readonly(cls, value: str) -> str:
        """Reject any scope that is not exactly the read-only Gmail scope."""
        if value.strip() != _READONLY_SCOPE:
            raise ValueError(
                "Gmail scope must be exactly the read-only scope "
                f"({_READONLY_SCOPE}); the connector never requests write access."
            )
        return value

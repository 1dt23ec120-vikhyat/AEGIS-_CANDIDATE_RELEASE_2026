"""Secret redaction for log records.

Provides a Loguru patcher that scrubs sensitive values from the structured
context (``record["extra"]``) of every log record, and helper functions for
redacting mappings before they are logged. This enforces the requirement that
secrets are never written to logs (NFR §7).

Two additional safeguards complement this module:

* Pydantic ``SecretStr`` values mask themselves in ``str``/``repr``, so logging
  a secret object directly is already safe.
* The logging configuration disables Loguru's ``diagnose`` outside development,
  preventing exception tracebacks from exposing local variable values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from loguru import Record

REDACTED: str = "***REDACTED***"

# Substrings that mark a context key as sensitive (matched case-insensitively).
_SENSITIVE_KEY_MARKERS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "credential",
        "private_key",
        "session_id",
    }
)

# Context keys that are known-safe and must never be redacted.
_ALLOWLIST: frozenset[str] = frozenset({"name", "audit"})


def _is_sensitive(key: str) -> bool:
    """Return whether a context key should be treated as sensitive."""
    lowered = key.lower()
    if lowered in _ALLOWLIST:
        return False
    return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``data`` with sensitive values redacted.

    Nested mappings are redacted recursively. Non-mapping values under a
    sensitive key are replaced with the redaction marker.

    Args:
        data: The mapping to redact.

    Returns:
        A new mapping safe to log.
    """
    result: dict[str, Any] = {}
    for key, value in data.items():
        if _is_sensitive(key):
            result[key] = REDACTED
        elif isinstance(value, dict):
            result[key] = redact_mapping(value)
        else:
            result[key] = value
    return result


def _redact_in_place(data: dict[str, Any]) -> None:
    """Redact sensitive values within ``data`` in place."""
    for key, value in list(data.items()):
        if _is_sensitive(key):
            data[key] = REDACTED
        elif isinstance(value, dict):
            _redact_in_place(value)


def patch_record(record: Record) -> None:
    """Loguru patcher: guarantee a ``name`` context key and redact secrets.

    Runs for every record before it reaches any sink. It ensures the structured
    context always carries a ``name`` (falling back to the source module) so the
    log format never fails, then redacts sensitive keys in the context.

    Args:
        record: The Loguru record being emitted (mutated in place).
    """
    extra = record["extra"]
    extra.setdefault("name", record["name"])
    _redact_in_place(extra)

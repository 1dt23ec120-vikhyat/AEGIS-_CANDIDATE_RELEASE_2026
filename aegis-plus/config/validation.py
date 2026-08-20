"""Environment-aware configuration validation.

Per-field validation is handled by the section schemas. This module adds
cross-field and environment-dependent rules that cannot be expressed on a
single field - most importantly, hardening requirements that apply only in
production.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from config import defaults
from config.exceptions import ConfigurationValidationError

if TYPE_CHECKING:
    from config.settings import Settings


def validate_settings(settings: Settings) -> None:
    """Validate cross-field and environment-specific configuration rules.

    Args:
        settings: The fully constructed settings aggregate.

    Raises:
        ConfigurationValidationError: If any rule is violated. All violations
            are collected and reported together.
    """
    errors: list[str] = []

    if settings.application.environment.is_production:
        _validate_production(settings, errors)

    if errors:
        joined = "; ".join(errors)
        raise ConfigurationValidationError(
            f"Configuration invalid for '{settings.application.environment.value}' "
            f"environment: {joined}."
        )


def _validate_production(settings: Settings, errors: list[str]) -> None:
    """Append production hardening violations to ``errors``.

    Args:
        settings: The settings aggregate.
        errors: Accumulator of human-readable violation messages.
    """
    if settings.application.debug:
        errors.append("debug mode must be disabled in production")

    secret = settings.security.secret_key.get_secret_value()
    if secret == defaults.INSECURE_SECRET_SENTINEL:
        errors.append("a real secret key must be configured (AEGIS_SECRET_KEY)")
    elif len(secret) < defaults.MIN_SECRET_KEY_LENGTH:
        errors.append(f"secret key must be at least {defaults.MIN_SECRET_KEY_LENGTH} characters")

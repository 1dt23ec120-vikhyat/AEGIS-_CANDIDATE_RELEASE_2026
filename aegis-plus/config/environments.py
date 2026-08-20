"""Application environment definitions.

Defines the set of runtime environments AEGIS+ recognizes and provides safe
parsing from arbitrary string input (for example, the ``AEGIS_ENV`` variable).
"""

from __future__ import annotations

from enum import Enum

from config.exceptions import ConfigurationValidationError


class Environment(str, Enum):
    """Supported runtime environments.

    Inherits from :class:`str` so values serialize naturally and compare
    directly against plain strings.
    """

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"

    @classmethod
    def from_string(cls, value: str) -> Environment:
        """Parse an environment from a string, case-insensitively.

        Args:
            value: The raw environment name (e.g. ``"Production"``).

        Returns:
            The matching :class:`Environment` member.

        Raises:
            ConfigurationValidationError: If ``value`` is not a known
                environment.
        """
        normalized = value.strip().lower()
        try:
            return cls(normalized)
        except ValueError as exc:
            valid = ", ".join(member.value for member in cls)
            raise ConfigurationValidationError(
                f"Unknown environment '{value}'. Valid environments: {valid}."
            ) from exc

    @property
    def is_production(self) -> bool:
        """Whether this environment is production."""
        return self is Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        """Whether this environment is development."""
        return self is Environment.DEVELOPMENT

    @property
    def is_testing(self) -> bool:
        """Whether this environment is testing."""
        return self is Environment.TESTING

"""Configuration exception hierarchy.

The configuration package is a foundational *leaf*: it is read during
bootstrap, before the core layer is active, and therefore does not depend on
any internal package. It defines its own minimal exception hierarchy here.

Reconciliation with the centralized ``core.exceptions`` hierarchy is scheduled
for the core-primitives work package; see ``IMPLEMENTATION_LOG.md``.
"""


class ConfigurationError(Exception):
    """Base class for all configuration-related errors."""


class ConfigurationFileError(ConfigurationError):
    """Raised when a configuration file cannot be read or parsed.

    Typically indicates a missing required file or malformed YAML. The message
    should identify the offending file to aid diagnosis (NFR §4 - detect
    corrupted configuration files).
    """


class ConfigurationValidationError(ConfigurationError):
    """Raised when configuration values fail validation.

    Covers both per-field validation (invalid types or ranges) and
    environment-aware cross-field rules (for example, debug mode enabled in a
    production environment).
    """

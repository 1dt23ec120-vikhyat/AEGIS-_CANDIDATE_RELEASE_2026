"""Configuration loading and precedence merging.

Loading precedence, lowest to highest:

1. Schema defaults (declared on the section models).
2. YAML files in the ``config/`` directory.
3. Environment variables (``AEGIS_*``), optionally sourced from a ``.env`` file.

Secrets (the secret key, and any future API keys) are only ever read from the
environment; they are never loaded from YAML (NFR §7).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from config.exceptions import ConfigurationFileError
from config.paths import ProjectPaths

# YAML files contributing configuration sections. ``application.yaml`` may
# contribute both the ``application`` and ``backend`` top-level keys.
_SECTION_FILES: tuple[str, ...] = (
    "application.yaml",
    "database.yaml",
    "logging.yaml",
    "security.yaml",
    "ui.yaml",
    "ai.yaml",
    "copilot.yaml",
    "gmail.yaml",
)


def _to_bool(value: str) -> bool:
    """Parse a boolean from a string environment value."""
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Environment variable -> (section, field, caster).
_ENV_OVERRIDES: dict[str, tuple[str, str, Callable[[str], Any]]] = {
    "AEGIS_ENV": ("application", "environment", str),
    "AEGIS_DEBUG": ("application", "debug", _to_bool),
    "AEGIS_BACKEND_HOST": ("backend", "host", str),
    "AEGIS_BACKEND_PORT": ("backend", "port", int),
    "AEGIS_DATABASE_URL": ("database", "url", str),
    "AEGIS_DATABASE_ECHO": ("database", "echo", _to_bool),
    "AEGIS_LOG_LEVEL": ("logging", "level", str),
    "AEGIS_LOG_DIR": ("logging", "directory", str),
    "AEGIS_SECRET_KEY": ("security", "secret_key", str),
    "AEGIS_SESSION_TIMEOUT_MINUTES": ("security", "session_timeout_minutes", int),
    "AEGIS_THEME": ("ui", "theme", str),
    "AEGIS_LANGUAGE": ("ui", "language", str),
    "AEGIS_MODELS_DIR": ("ai", "models_dir", str),
    "AEGIS_COPILOT_ENABLED": ("copilot", "enabled", _to_bool),
    "AEGIS_COPILOT_PROVIDER": ("copilot", "provider", str),
    "AEGIS_COPILOT_MODEL": ("copilot", "model", str),
    "AEGIS_GMAIL_ENABLED": ("gmail", "enabled", _to_bool),
    "AEGIS_GMAIL_CLIENT_ID": ("gmail", "client_id", str),
}


def load_env_file(paths: ProjectPaths) -> None:
    """Load a local ``.env`` file into the process environment, if present.

    Missing ``.env`` files are not an error; environment variables set directly
    in the process take precedence and are left untouched.

    Args:
        paths: Resolved project paths.
    """
    if paths.env_file.exists():
        load_dotenv(paths.env_file, override=False)


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Load a single YAML file into a mapping.

    Args:
        path: Path to the YAML file.

    Returns:
        The parsed mapping, or an empty dict if the file does not exist.

    Raises:
        ConfigurationFileError: If the file cannot be parsed or does not contain
            a top-level mapping.
    """
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            content = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigurationFileError(
            f"Failed to parse configuration file '{path.name}': {exc}"
        ) from exc
    if content is None:
        return {}
    if not isinstance(content, dict):
        raise ConfigurationFileError(
            f"Configuration file '{path.name}' must contain a mapping at the top level."
        )
    return content


def read_yaml_config(paths: ProjectPaths) -> dict[str, Any]:
    """Read and merge all YAML section files.

    Args:
        paths: Resolved project paths.

    Returns:
        A nested mapping keyed by configuration section.

    Raises:
        ConfigurationFileError: If any file is malformed.
    """
    merged: dict[str, Any] = {}
    for file_name in _SECTION_FILES:
        section = _load_yaml_file(paths.config_file(file_name))
        _deep_merge(merged, section)
    return merged


def collect_env_overrides(environ: Mapping[str, str]) -> dict[str, Any]:
    """Build a nested override mapping from ``AEGIS_*`` environment variables.

    Args:
        environ: The environment mapping to read from.

    Returns:
        A nested mapping (section -> field -> value) for every recognized and
        present variable.
    """
    overrides: dict[str, Any] = {}
    for env_name, (section, field, caster) in _ENV_OVERRIDES.items():
        raw = environ.get(env_name)
        if raw is None:
            continue
        overrides.setdefault(section, {})[field] = caster(raw)
    return overrides


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into ``base`` in place.

    Args:
        base: The mapping to merge into (mutated).
        override: The mapping whose values take precedence.

    Returns:
        The mutated ``base`` mapping.
    """
    for key, value in override.items():
        existing = base.get(key)
        if isinstance(existing, dict) and isinstance(value, Mapping):
            _deep_merge(existing, value)
        else:
            base[key] = value
    return base


def build_config_mapping(
    paths: ProjectPaths, environ: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Produce the merged configuration mapping (YAML overlaid by environment).

    Schema defaults are applied later by the section models for any section or
    field left unspecified here.

    Args:
        paths: Resolved project paths.
        environ: Environment mapping. Defaults to ``os.environ``.

    Returns:
        The merged configuration mapping ready for schema validation.
    """
    source_environ = os.environ if environ is None else environ
    mapping = read_yaml_config(paths)
    _deep_merge(mapping, collect_env_overrides(source_environ))
    return mapping

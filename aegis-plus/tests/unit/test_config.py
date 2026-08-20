"""Unit tests for the configuration subsystem."""

from __future__ import annotations

from pathlib import Path

import pytest

from config import (
    ConfigurationFileError,
    ConfigurationValidationError,
    Environment,
    ProjectPaths,
    load_settings,
)
from config.loader import build_config_mapping, collect_env_overrides

pytestmark = pytest.mark.unit


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def project_root(tmp_path: Path) -> ProjectPaths:
    """A temporary project root with an empty config directory."""
    (tmp_path / "config").mkdir()
    return ProjectPaths.create(root=tmp_path)


def test_defaults_apply_when_no_files_or_env(project_root: ProjectPaths) -> None:
    settings = load_settings(project_root, environ={}, use_env_file=False)

    assert settings.application.name == "AEGIS+"
    assert settings.application.environment is Environment.DEVELOPMENT
    assert settings.backend.host == "127.0.0.1"
    assert settings.backend.port == 8137
    assert settings.database.url.startswith("sqlite:///")
    assert settings.logging.level == "INFO"
    assert settings.ui.theme == "dark"


def test_yaml_values_override_defaults(project_root: ProjectPaths) -> None:
    _write(project_root.config_file("ui.yaml"), 'ui:\n  theme: "light"\n')
    _write(project_root.config_file("logging.yaml"), 'logging:\n  level: "warning"\n')

    settings = load_settings(project_root, environ={}, use_env_file=False)

    assert settings.ui.theme == "light"
    assert settings.logging.level == "WARNING"  # normalized to upper-case


def test_environment_overrides_yaml(project_root: ProjectPaths) -> None:
    _write(project_root.config_file("ui.yaml"), 'ui:\n  theme: "light"\n')

    settings = load_settings(
        project_root,
        environ={"AEGIS_THEME": "enterprise", "AEGIS_BACKEND_PORT": "9001"},
        use_env_file=False,
    )

    assert settings.ui.theme == "enterprise"  # env beats YAML
    assert settings.backend.port == 9001  # cast from string to int


def test_env_override_casts_types() -> None:
    overrides = collect_env_overrides({"AEGIS_DEBUG": "false", "AEGIS_BACKEND_PORT": "8200"})
    assert overrides["application"]["debug"] is False
    assert overrides["backend"]["port"] == 8200


def test_corrupted_yaml_raises_file_error(project_root: ProjectPaths) -> None:
    _write(project_root.config_file("database.yaml"), "database:\n  url: [unclosed\n")

    with pytest.raises(ConfigurationFileError) as exc:
        build_config_mapping(project_root, environ={})

    assert "database.yaml" in str(exc.value)


def test_non_mapping_yaml_raises_file_error(project_root: ProjectPaths) -> None:
    _write(project_root.config_file("ui.yaml"), "- just\n- a\n- list\n")

    with pytest.raises(ConfigurationFileError):
        build_config_mapping(project_root, environ={})


def test_invalid_log_level_raises_validation_error(project_root: ProjectPaths) -> None:
    _write(project_root.config_file("logging.yaml"), 'logging:\n  level: "LOUD"\n')

    with pytest.raises(ConfigurationValidationError):
        load_settings(project_root, environ={}, use_env_file=False)


def test_unknown_config_key_is_rejected(project_root: ProjectPaths) -> None:
    _write(project_root.config_file("ui.yaml"), 'ui:\n  colour: "blue"\n')

    with pytest.raises(ConfigurationValidationError):
        load_settings(project_root, environ={}, use_env_file=False)


def test_production_rejects_debug_and_default_secret(
    project_root: ProjectPaths,
) -> None:
    with pytest.raises(ConfigurationValidationError) as exc:
        load_settings(
            project_root,
            environ={"AEGIS_ENV": "production", "AEGIS_DEBUG": "true"},
            use_env_file=False,
        )

    message = str(exc.value)
    assert "debug" in message
    assert "secret key" in message


def test_production_accepts_hardened_configuration(
    project_root: ProjectPaths,
) -> None:
    settings = load_settings(
        project_root,
        environ={
            "AEGIS_ENV": "production",
            "AEGIS_DEBUG": "false",
            "AEGIS_SECRET_KEY": "x" * 48,
        },
        use_env_file=False,
    )

    assert settings.application.environment.is_production
    assert settings.security.is_secret_configured


def test_secret_is_masked_in_repr(project_root: ProjectPaths) -> None:
    settings = load_settings(
        project_root,
        environ={"AEGIS_SECRET_KEY": "super-secret-value-1234567890"},
        use_env_file=False,
    )

    assert "super-secret-value" not in repr(settings)
    assert settings.security.secret_key.get_secret_value() == ("super-secret-value-1234567890")


def test_paths_resolve_relative_to_root(tmp_path: Path) -> None:
    paths = ProjectPaths.create(root=tmp_path)

    assert paths.resolve("logs") == (tmp_path / "logs").resolve()
    assert paths.config_file("ai.yaml") == tmp_path / "config" / "ai.yaml"

    absolute = tmp_path / "elsewhere"
    assert paths.resolve(absolute) == absolute.resolve()

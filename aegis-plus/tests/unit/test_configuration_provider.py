"""Unit tests for the infrastructure ConfigurationProvider adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from config import ProjectPaths, load_settings
from core.exceptions import ConfigurationValidationError
from core.interfaces import IConfigurationProvider
from infrastructure.configuration import ConfigurationProvider

pytestmark = pytest.mark.unit


@pytest.fixture
def project_root(tmp_path: Path) -> ProjectPaths:
    (tmp_path / "config").mkdir()
    return ProjectPaths.create(root=tmp_path)


def test_provider_implements_core_port(project_root: ProjectPaths) -> None:
    settings = load_settings(project_root, environ={}, use_env_file=False)
    provider = ConfigurationProvider(settings)

    assert isinstance(provider, IConfigurationProvider)
    assert provider.environment() == "development"
    assert provider.is_debug() is True
    assert provider.database_url().startswith("sqlite:///")
    assert provider.database_echo() is False
    assert provider.log_level() == "INFO"


def test_provider_exposes_overridden_values(project_root: ProjectPaths) -> None:
    settings = load_settings(
        project_root,
        environ={"AEGIS_ENV": "production", "AEGIS_DEBUG": "false", "AEGIS_SECRET_KEY": "y" * 40},
        use_env_file=False,
    )
    provider = ConfigurationProvider(settings)

    assert provider.environment() == "production"
    assert provider.is_debug() is False


def test_load_maps_leaf_errors_into_core(
    project_root: ProjectPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force get_settings() to raise a leaf validation error via a bad log level.
    (project_root.config_file("logging.yaml")).write_text(
        'logging:\n  level: "NOISY"\n', encoding="utf-8"
    )

    import config

    def _raise_from_repo_root() -> object:
        return load_settings(project_root, environ={}, use_env_file=False)

    monkeypatch.setattr(config, "get_settings", _raise_from_repo_root)
    monkeypatch.setattr("infrastructure.configuration.provider.get_settings", _raise_from_repo_root)

    with pytest.raises(ConfigurationValidationError):
        ConfigurationProvider.load()

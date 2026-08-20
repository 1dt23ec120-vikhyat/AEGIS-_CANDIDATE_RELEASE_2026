"""Unit tests for the centralized logging and audit subsystem."""

from __future__ import annotations

import json
import logging as stdlib_logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr

from config import Environment, ProjectPaths
from config.schemas import LoggingSettings
from core.interfaces import ILogger
from infrastructure.logging import (
    AuditLogger,
    configure_logging,
    get_logger,
    is_configured,
    reset_logging,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_logging_after_test() -> Iterator[None]:
    """Ensure a clean logging state around every test."""
    yield
    reset_logging()


@pytest.fixture
def log_paths(tmp_path: Path) -> ProjectPaths:
    """Project paths rooted at a temporary directory."""
    return ProjectPaths.create(root=tmp_path)


def _configure(paths: ProjectPaths, level: str = "INFO") -> None:
    configure_logging(
        LoggingSettings(level=level),
        paths,
        environment=Environment.TESTING,
        enqueue=False,
    )


def _read(paths: ProjectPaths, name: str) -> str:
    return (paths.logs_dir / name).read_text(encoding="utf-8")


def test_configure_creates_log_files(log_paths: ProjectPaths) -> None:
    _configure(log_paths)
    get_logger("test").info("hello world")
    reset_logging()

    assert (log_paths.logs_dir / "aegis.log").exists()
    assert (log_paths.logs_dir / "audit.log").exists()
    assert "hello world" in _read(log_paths, "aegis.log")


def test_is_configured_reflects_state(log_paths: ProjectPaths) -> None:
    assert is_configured() is False
    _configure(log_paths)
    assert is_configured() is True
    reset_logging()
    assert is_configured() is False


def test_level_filtering_suppresses_debug(log_paths: ProjectPaths) -> None:
    _configure(log_paths, level="INFO")
    log = get_logger("test")
    log.debug("suppressed-debug")
    log.info("visible-info")
    reset_logging()

    content = _read(log_paths, "aegis.log")
    assert "suppressed-debug" not in content
    assert "visible-info" in content


def test_secretstr_is_masked_in_messages(log_paths: ProjectPaths) -> None:
    _configure(log_paths)
    secret = SecretStr("top-secret-token-value")
    get_logger("test").info("token is {}", secret)
    reset_logging()

    content = _read(log_paths, "aegis.log")
    assert "top-secret-token-value" not in content
    assert "*****" in content


def test_audit_context_is_redacted(log_paths: ProjectPaths) -> None:
    _configure(log_paths)
    audit = AuditLogger(get_logger("security"))
    audit.success("user.login", actor="alice", password="hunter2")
    reset_logging()

    audit_content = _read(log_paths, "audit.log")
    assert "hunter2" not in audit_content
    assert "REDACTED" in audit_content


def test_audit_record_is_structured(log_paths: ProjectPaths) -> None:
    _configure(log_paths)
    audit = AuditLogger(get_logger("security"))
    audit.success("application.start", actor="system")
    reset_logging()

    lines = _read(log_paths, "audit.log").strip().splitlines()
    payload = json.loads(lines[-1])
    extra = payload["record"]["extra"]
    assert extra["audit"] is True
    assert extra["action"] == "application.start"
    assert extra["outcome"] == "success"
    assert extra["actor"] == "system"


def test_non_audit_records_excluded_from_audit_log(log_paths: ProjectPaths) -> None:
    _configure(log_paths)
    get_logger("test").info("ordinary-message")
    reset_logging()

    assert "ordinary-message" not in _read(log_paths, "audit.log")


def test_stdlib_logging_is_bridged(log_paths: ProjectPaths) -> None:
    _configure(log_paths)
    stdlib_logging.getLogger("uvicorn").warning("bridged-from-stdlib")
    reset_logging()

    assert "bridged-from-stdlib" in _read(log_paths, "aegis.log")


def test_get_logger_satisfies_protocol(log_paths: ProjectPaths) -> None:
    _configure(log_paths)
    log = get_logger("test")
    assert isinstance(log, ILogger)
    bound = log.bind(request_id="abc")
    assert isinstance(bound, ILogger)

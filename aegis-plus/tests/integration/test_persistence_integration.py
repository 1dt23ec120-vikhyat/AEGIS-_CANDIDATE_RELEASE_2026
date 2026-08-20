"""Integration tests: audit persistence and Alembic migrations."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from config import Environment, ProjectPaths, reset_settings_cache
from config.schemas import LoggingSettings
from core.entities import AuditLog
from infrastructure.database import Database, SqlAlchemyUnitOfWork
from infrastructure.logging import AuditLogger, configure_logging, get_logger, reset_logging

pytestmark = pytest.mark.integration


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(f"sqlite:///{tmp_path / 'test.db'}")
    db.create_all()
    yield db
    db.dispose()


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    reset_logging()


def _configure_logging(tmp_path: Path) -> None:
    configure_logging(
        LoggingSettings(),
        ProjectPaths.create(root=tmp_path),
        environment=Environment.TESTING,
        enqueue=False,
    )


def test_audit_logger_persists_and_redacts(database: Database, tmp_path: Path) -> None:
    _configure_logging(tmp_path)
    audit = AuditLogger(
        get_logger("security"),
        unit_of_work_factory=lambda: SqlAlchemyUnitOfWork(database.session_factory),
    )

    audit.success("application.start", actor="system", api_key="SECRET-VALUE")

    with SqlAlchemyUnitOfWork(database.session_factory) as uow:
        rows = uow.get_repository(AuditLog).list()

    assert len(rows) == 1
    assert rows[0].action == "application.start"
    assert rows[0].actor == "system"
    assert rows[0].context.get("api_key") == "***REDACTED***"


def test_audit_persistence_failure_does_not_raise(database: Database, tmp_path: Path) -> None:
    _configure_logging(tmp_path)

    def _failing_factory() -> SqlAlchemyUnitOfWork:
        raise RuntimeError("database unavailable")

    audit = AuditLogger(get_logger("security"), unit_of_work_factory=_failing_factory)

    # Must not propagate; auditing can never break the caller.
    audit.success("application.start")


def test_audit_logger_without_persistence_only_logs(database: Database, tmp_path: Path) -> None:
    _configure_logging(tmp_path)
    audit = AuditLogger(get_logger("security"))  # no persistence

    audit.success("application.start")

    with SqlAlchemyUnitOfWork(database.session_factory) as uow:
        assert uow.get_repository(AuditLog).list() == []


def test_migration_upgrade_creates_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from alembic import command
    from alembic.config import Config

    db_file = tmp_path / "migrated.db"
    monkeypatch.setenv("AEGIS_DATABASE_URL", f"sqlite:///{db_file}")
    reset_settings_cache()
    try:
        command.upgrade(Config("alembic.ini"), "head")
    finally:
        reset_settings_cache()

    connection = sqlite3.connect(db_file)
    try:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    finally:
        connection.close()

    assert {"audit_logs", "configurations"} <= tables

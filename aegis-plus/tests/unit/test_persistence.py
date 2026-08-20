"""Unit tests for the persistence foundation (repositories and Unit of Work)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from core.constants import AuditOutcome
from core.entities import AuditLog, Configuration
from core.entities.base import BaseEntity
from infrastructure.database import Database, SqlAlchemyUnitOfWork

pytestmark = pytest.mark.unit


class _Unregistered(BaseEntity):
    """Entity with no registered repository, for negative testing."""


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(f"sqlite:///{tmp_path / 'test.db'}")
    db.create_all()
    yield db
    db.dispose()


def _uow(database: Database) -> SqlAlchemyUnitOfWork:
    return SqlAlchemyUnitOfWork(database.session_factory)


def _sample_audit() -> AuditLog:
    return AuditLog(
        action="user.login",
        outcome=AuditOutcome.SUCCESS,
        actor="alice",
        context={"ip": "127.0.0.1"},
    )


def test_add_then_get_round_trips(database: Database) -> None:
    entry = _sample_audit()
    with _uow(database) as uow:
        uow.get_repository(AuditLog).add(entry)
        uow.commit()

    with _uow(database) as uow:
        loaded = uow.get_repository(AuditLog).get(entry.id)

    assert loaded is not None
    assert loaded == entry  # identity equality
    assert loaded.action == "user.login"
    assert loaded.outcome is AuditOutcome.SUCCESS
    assert loaded.context == {"ip": "127.0.0.1"}


def test_commit_is_required_to_persist(database: Database) -> None:
    entry = _sample_audit()
    with _uow(database) as uow:
        uow.get_repository(AuditLog).add(entry)
        # No commit -> discarded on exit.

    with _uow(database) as uow:
        assert uow.get_repository(AuditLog).get(entry.id) is None


def test_update_persists_changes(database: Database) -> None:
    config = Configuration(key="theme", value="dark")
    with _uow(database) as uow:
        uow.get_repository(Configuration).add(config)
        uow.commit()

    config.value = "light"
    config.touch()
    with _uow(database) as uow:
        uow.get_repository(Configuration).update(config)
        uow.commit()

    with _uow(database) as uow:
        loaded = uow.get_repository(Configuration).get(config.id)
    assert loaded is not None
    assert loaded.value == "light"


def test_delete_removes_entity(database: Database) -> None:
    entry = _sample_audit()
    with _uow(database) as uow:
        uow.get_repository(AuditLog).add(entry)
        uow.commit()

    with _uow(database) as uow:
        uow.get_repository(AuditLog).delete(entry.id)
        uow.commit()

    with _uow(database) as uow:
        assert uow.get_repository(AuditLog).get(entry.id) is None


def test_list_returns_all(database: Database) -> None:
    with _uow(database) as uow:
        repo = uow.get_repository(AuditLog)
        repo.add(_sample_audit())
        repo.add(_sample_audit())
        uow.commit()

    with _uow(database) as uow:
        assert len(uow.get_repository(AuditLog).list()) == 2


def test_unit_of_work_is_atomic_across_repositories(database: Database) -> None:
    audit = _sample_audit()
    config = Configuration(key="k", value="v")

    # Both writes share one transaction; without commit, neither persists.
    with _uow(database) as uow:
        uow.get_repository(AuditLog).add(audit)
        uow.get_repository(Configuration).add(config)

    with _uow(database) as uow:
        assert uow.get_repository(AuditLog).get(audit.id) is None
        assert uow.get_repository(Configuration).get(config.id) is None

    # Committed together -> both persist.
    with _uow(database) as uow:
        uow.get_repository(AuditLog).add(audit)
        uow.get_repository(Configuration).add(config)
        uow.commit()

    with _uow(database) as uow:
        assert uow.get_repository(AuditLog).get(audit.id) is not None
        assert uow.get_repository(Configuration).get(config.id) is not None


def test_get_repository_for_unregistered_entity_raises(database: Database) -> None:
    with _uow(database) as uow, pytest.raises(KeyError):
        uow.get_repository(_Unregistered)


def test_get_repository_outside_context_raises(database: Database) -> None:
    with pytest.raises(RuntimeError):
        _uow(database).get_repository(AuditLog)

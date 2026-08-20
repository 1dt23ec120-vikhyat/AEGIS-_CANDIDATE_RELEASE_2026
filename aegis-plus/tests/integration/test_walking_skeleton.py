"""Walking-skeleton integration test.

Exercises the full end-to-end path in a single run: configuration loading,
logging initialization, database migrations, connectivity verification, the
embedded backend, the UI's HTTP client, and the first persisted audit event -
UI client -> FastAPI -> health/persistence -> database.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import ProjectPaths, Settings, load_settings
from core.constants import AuditOutcome
from core.entities import AuditLog
from infrastructure.logging import reset_logging
from ui.backend.client import BackendClient

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    reset_logging()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    (tmp_path / "config").mkdir()
    db_file = tmp_path / "aegis.db"
    return load_settings(
        ProjectPaths.create(root=tmp_path),
        environ={
            "AEGIS_DATABASE_URL": f"sqlite:///{db_file}",
            "AEGIS_BACKEND_PORT": str(_free_port()),
        },
        use_env_file=False,
    )


@pytest.fixture
def lifecycle(
    settings: Settings, tmp_path: Path
) -> Iterator[tuple[DependencyContainer, ApplicationLifecycle]]:
    container = DependencyContainer(settings, paths=ProjectPaths.create(root=tmp_path))
    life = ApplicationLifecycle(container)
    yield container, life
    life.stop()


def test_startup_migrates_schema_and_persists_first_audit_event(
    lifecycle: tuple[DependencyContainer, ApplicationLifecycle],
) -> None:
    container, life = lifecycle
    life.start()

    # Migrations ran end-to-end: the audit event was persisted through the
    # repository and Unit of Work into the database.
    with container.unit_of_work_factory() as uow:
        logs = uow.get_repository(AuditLog).list()

    starts = [log for log in logs if log.action == "application.start"]
    assert len(starts) == 1
    assert starts[0].outcome is AuditOutcome.SUCCESS


def test_backend_reachable_through_ui_client(
    lifecycle: tuple[DependencyContainer, ApplicationLifecycle],
) -> None:
    container, life = lifecycle
    life.start()

    client = BackendClient(container.backend_server.base_url)
    assert client.liveness().ok is True
    assert client.readiness().ok is True

    identity = client.identity()
    assert identity.get("name") == "AEGIS+"


def test_lifecycle_stops_cleanly(
    lifecycle: tuple[DependencyContainer, ApplicationLifecycle],
) -> None:
    container, life = lifecycle
    life.start()
    assert container.backend_server.is_running

    life.stop()
    assert not container.backend_server.is_running

    # A second liveness probe should now fail (backend stopped).
    client = BackendClient(container.backend_server.base_url)
    assert client.liveness().ok is False

"""End-to-end integration tests for the file analysis API."""

from __future__ import annotations

import shutil
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import ProjectPaths, Settings, load_settings
from core.entities import FileScan
from infrastructure.logging import reset_logging
from tests.integration._auth import install_auth

_MODEL = Path(__file__).resolve().parents[2] / "models" / "url_lightgbm.txt"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    reset_logging()


@pytest.fixture
def running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[DependencyContainer, str]]:
    (tmp_path / "config").mkdir()
    if _MODEL.exists():
        (tmp_path / "models").mkdir()
        shutil.copy(_MODEL, tmp_path / "models" / "url_lightgbm.txt")
    settings: Settings = load_settings(
        ProjectPaths.create(root=tmp_path),
        environ={
            "AEGIS_DATABASE_URL": f"sqlite:///{tmp_path / 'aegis.db'}",
            "AEGIS_BACKEND_PORT": str(_free_port()),
        },
        use_env_file=False,
    )
    container = DependencyContainer(settings, paths=ProjectPaths.create(root=tmp_path))
    life = ApplicationLifecycle(container)
    life.start()
    install_auth(monkeypatch, container.backend_server.base_url)
    yield container, container.backend_server.base_url
    life.stop()


_MACRO_DOC = b'\xd0\xcf\x11\xe0 Auto_Open Shell("cmd.exe") vba_project macros/vba'
_BENIGN = b"Quarterly report. Everything nominal. Contact ceo@corp.example.\n"
_DROPPER_EXE = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00 this program cannot be run in DOS mode"


def _scan(base_url: str, filename: str, data: bytes) -> dict[str, Any]:
    response = httpx.post(
        f"{base_url}/api/files/scan",
        files={"upload": (filename, data)},
        timeout=10.0,
    )
    assert response.status_code == 200
    result: dict[str, Any] = response.json()
    return result


def test_file_scan_detects_macro_document_and_persists(
    running: tuple[DependencyContainer, str],
) -> None:
    container, base_url = running
    body = _scan(base_url, "invoice.docm", _MACRO_DOC)
    assert body["verdict"] == "phishing"
    assert body["category"] == "malicious_document"
    assert body["sha256"]
    assert body["overview"]["md5"]
    assert body["malicious"] is True

    recent = httpx.get(f"{base_url}/api/files/scans/recent", timeout=10.0).json()
    assert any(item["sha256"] == body["sha256"] for item in recent)

    with container.unit_of_work_factory() as uow:
        stored = uow.get_repository(FileScan).list()
    assert len(stored) == 1
    # No raw bytes are persisted - only fingerprints and derived findings.
    assert stored[0].sha256 == body["sha256"]


def test_malicious_file_is_blacklisted_and_correlated(
    running: tuple[DependencyContainer, str],
) -> None:
    _, base_url = running
    body = _scan(base_url, "payload.pdf.exe", _DROPPER_EXE)
    assert body["malicious"] is True
    # Recorded to threat intelligence as a FILE artifact.
    threats = httpx.get(f"{base_url}/api/threats", timeout=10.0).json()
    assert any(t["artifact_type"] == "file" for t in threats)
    # Correlated into an incident.
    assert body["incident_id"]
    assert body["incident_title"]


def test_benign_file_is_not_malicious(running: tuple[DependencyContainer, str]) -> None:
    _, base_url = running
    body = _scan(base_url, "notes.txt", _BENIGN)
    assert body["verdict"] == "legitimate"
    assert body["malicious"] is False
    assert body["incident_id"] == ""


def test_empty_file_returns_422(running: tuple[DependencyContainer, str]) -> None:
    _, base_url = running
    response = httpx.post(
        f"{base_url}/api/files/scan", files={"upload": ("empty.bin", b"")}, timeout=10.0
    )
    assert response.status_code == 422


def test_file_investigation_roundtrip(running: tuple[DependencyContainer, str]) -> None:
    _, base_url = running
    body = _scan(base_url, "invoice.docm", _MACRO_DOC)
    scan_id = body["id"]

    default = httpx.get(f"{base_url}/api/files/investigations/{scan_id}", timeout=10.0).json()
    assert default["status"] == "open"

    updated = httpx.put(
        f"{base_url}/api/files/investigations/{scan_id}",
        json={
            "status": "confirmed_threat",
            "priority": "high",
            "tags": ["malware", "macro"],
            "notes": "Confirmed malicious macro document.",
        },
        timeout=10.0,
    ).json()
    assert updated["status"] == "confirmed_threat"
    assert updated["priority"] == "high"
    assert "macro" in updated["tags"]

    reread = httpx.get(f"{base_url}/api/files/investigations/{scan_id}", timeout=10.0).json()
    assert reread["notes"] == "Confirmed malicious macro document."


def test_file_scan_feeds_soc_overview(running: tuple[DependencyContainer, str]) -> None:
    _, base_url = running
    _scan(base_url, "payload.pdf.exe", _DROPPER_EXE)
    overview = httpx.get(f"{base_url}/api/soc/overview", timeout=10.0).json()
    threat_metrics = {m["label"]: m["value"] for m in overview["threat_metrics"]}
    assert "Malicious files" in threat_metrics

"""End-to-end tests for the live intelligence pipeline (M10).

Proves the full flow with the real dependency container: a detection service's
``analyze()`` publishes intelligence events onto the internal bus, the subscribed
``GraphBuilder`` consumes them, and the knowledge graph is populated live — with
no direct graph calls from the detection code.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import ProjectPaths, Settings, load_settings
from core.domain.events import EventType
from infrastructure.logging import reset_logging

_PHISHING = "http://192.168.10.5/login@paypal-verify-account-secure.example.com/signin"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    reset_logging()
    yield
    reset_logging()


@pytest.fixture
def container(tmp_path: Path) -> Iterator[DependencyContainer]:
    (tmp_path / "config").mkdir()
    settings: Settings = load_settings(
        ProjectPaths.create(root=tmp_path),
        environ={
            "AEGIS_DATABASE_URL": f"sqlite:///{tmp_path / 'aegis.db'}",
            "AEGIS_BACKEND_PORT": str(_free_port()),
        },
        use_env_file=False,
    )
    built = DependencyContainer(settings, paths=ProjectPaths.create(root=tmp_path))
    life = ApplicationLifecycle(built)
    life.start()
    yield built
    life.stop()


def _node_types(container: DependencyContainer) -> dict[str, int]:
    return dict(container.graph_explorer.snapshot().node_type_counts)


def test_url_analysis_populates_graph_live(container: DependencyContainer) -> None:
    # Baseline: the live graph starts empty.
    assert container.graph_explorer.snapshot().node_count == 0

    container.url_analysis_service.analyze(_PHISHING)

    # A graph node now exists, created purely via the event bus + builder.
    snapshot = container.graph_explorer.snapshot()
    assert snapshot.node_count >= 1
    assert "url" in _node_types(container)
    # A malicious verdict also recorded a threat node.
    assert "threat" in _node_types(container)
    # The history recorded the artifact_analyzed event.
    assert container.event_history.recent_by_type(EventType.ARTIFACT_ANALYZED)
    # The publisher observed published events with no failures.
    metrics = container.intelligence_publisher.metrics()
    assert metrics["events_published"] >= 1.0
    assert metrics["publish_failures"] == 0.0


def test_file_analysis_populates_graph_live(container: DependencyContainer) -> None:
    container.file_analysis_service.analyze("sample.txt", b"harmless content")

    snapshot = container.graph_explorer.snapshot()
    assert snapshot.node_count >= 1
    assert "file" in _node_types(container)
    assert container.event_history.recent_by_type(EventType.ARTIFACT_ANALYZED)


def test_event_flow_dispatches_through_bus_to_graph(container: DependencyContainer) -> None:
    container.url_analysis_service.analyze(_PHISHING)

    bus_metrics = container.event_bus.metrics
    # Events were published and dispatched to subscribers (history + builder).
    assert int(bus_metrics["total_published"]) >= 1  # type: ignore[call-overload]
    assert int(bus_metrics["total_dispatched"]) >= 1  # type: ignore[call-overload]
    assert int(bus_metrics["total_failures"]) == 0  # type: ignore[call-overload]
    # The graph reflects the dispatched events.
    assert container.graph_explorer.snapshot().node_count >= 1


def test_multiple_analyses_accumulate_in_graph(container: DependencyContainer) -> None:
    container.url_analysis_service.analyze(_PHISHING)
    first = container.graph_explorer.snapshot().node_count
    container.url_analysis_service.analyze("https://another-distinct-benign.example/path")
    second = container.graph_explorer.snapshot().node_count
    assert second >= first
    # More than one URL artifact is now represented.
    assert _node_types(container).get("url", 0) >= 2


def test_health_surfaces_pipeline_observability(container: DependencyContainer) -> None:
    container.url_analysis_service.analyze(_PHISHING)
    names = {c.name: c for c in container.soc_service.overview().health}
    assert "intelligence-publisher" in names
    assert "graph-builder" in names
    assert "event-bus" in names
    assert names["intelligence-publisher"].status == "healthy"


_PHISH_EMAIL = (
    "From: PayPal Support <no-reply@paypal-secure-login.xyz>\n"
    "Reply-To: attacker@evil.example\n"
    "To: you@example.com\n"
    "Subject: Urgent: your account is suspended\n"
    "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n\n"
    "Verify immediately: http://192.168.10.5/login@paypal-verify.example.com/signin\n"
)


def test_email_analysis_populates_graph_live(container: DependencyContainer) -> None:
    container.email_analysis_service.analyze(_PHISH_EMAIL)

    snapshot = container.graph_explorer.snapshot()
    assert snapshot.node_count >= 1
    assert "email" in _node_types(container)
    assert container.event_history.recent_by_type(EventType.ARTIFACT_ANALYZED)
    # A malicious email opens an incident and campaign via correlation.
    assert container.event_history.recent_by_type(EventType.INCIDENT_CREATED)


def test_investigation_save_publishes_event(container: DependencyContainer) -> None:
    from core.constants import InvestigationPriority, InvestigationStatus

    outcome = container.email_analysis_service.analyze(_PHISH_EMAIL)
    scan_id = str(outcome.scan.id)

    container.email_investigation_service.save(
        scan_id,
        status=InvestigationStatus.UNDER_INVESTIGATION,
        priority=InvestigationPriority.HIGH,
        tags=("phishing",),
        notes="Escalated for review.",
    )
    assert container.event_history.recent_by_type(EventType.INVESTIGATION_COMPLETED)

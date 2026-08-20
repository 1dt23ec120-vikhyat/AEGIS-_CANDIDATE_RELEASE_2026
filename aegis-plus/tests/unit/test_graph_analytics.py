"""Tests for the Graph Analytics Engine (M11 Phase A)."""

from __future__ import annotations

from core.domain.events import (
    artifact_analyzed,
    campaign_created,
    incident_created,
    relationship_discovered,
    threat_recorded,
)
from infrastructure.graph import InMemoryGraphRepository
from services.analytics import GraphAnalyticsService
from services.events import InProcessEventBus
from services.graph import GraphBuilder, GraphQueryService


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
    def bind(self, **k: object) -> _FakeLogger:
        return self


def _analytics() -> GraphAnalyticsService:
    repo = InMemoryGraphRepository()
    bus = InProcessEventBus(_FakeLogger())
    GraphBuilder(repo, _FakeLogger()).attach(bus)
    bus.publish(
        artifact_analyzed(
            source="url-analysis",
            artifact_id="url-1",
            artifact_type="url",
            verdict="phishing",
            risk_score=0.9,
            category="credential_harvesting",
        )
    )
    bus.publish(
        artifact_analyzed(
            source="file-analysis",
            artifact_id="file-1",
            artifact_type="file",
            verdict="legitimate",
            risk_score=0.1,
            category="none",
        )
    )
    bus.publish(threat_recorded(source="ti", artifact_id="url-1", artifact_type="url"))
    bus.publish(
        incident_created(
            source="c", incident_id="inc-1", incident_title="Wave", artifact_id="url-1"
        )
    )
    bus.publish(campaign_created(source="c", campaign_id="camp-1", campaign_name="Camp"))
    for artifact, atype in (("url-1", "url"), ("file-1", "file")):
        bus.publish(
            relationship_discovered(
                source="ioc-fusion",
                source_id=artifact,
                source_type=atype,
                target_id="ioc-9",
                target_type="ioc",
                relationship="shares_ioc",
            )
        )
    return GraphAnalyticsService(GraphQueryService(repo), _FakeLogger())


def test_node_degree_and_rankings() -> None:
    svc = _analytics()
    assert svc.node_degree("url-1") >= 1
    degree = svc.degree_ranking(top=5)
    assert degree
    # Deterministic ordering: score desc then id asc.
    scores = [r.score for r in degree]
    assert scores == sorted(scores, reverse=True)
    central = svc.centrality_ranking(top=5)
    assert central
    assert all(0.0 <= r.score <= 1.0 for r in central)


def test_rankings_are_deterministic() -> None:
    svc = _analytics()
    assert svc.degree_ranking(top=10) == svc.degree_ranking(top=10)
    assert svc.centrality_ranking(top=10) == svc.centrality_ranking(top=10)


def test_component_and_density() -> None:
    svc = _analytics()
    comp = svc.component_analysis()
    assert comp.component_count >= 1
    assert comp.largest_size >= 2
    assert comp.sizes == tuple(sorted(comp.sizes, reverse=True))
    assert 0.0 <= svc.relationship_density() <= 1.0


def test_blast_radius_and_reachability() -> None:
    svc = _analytics()
    blast = svc.blast_radius("url-1", max_depth=3)
    assert blast.origin_id == "url-1"
    assert blast.reachable_count >= 1
    assert blast.reachable_ids == tuple(sorted(blast.reachable_ids))
    reach = svc.reachability("url-1", max_depth=3)
    assert reach.reachable_count >= 1
    assert reach.by_type


def test_threat_propagation_counts_threats() -> None:
    svc = _analytics()
    prop = svc.threat_propagation("url-1", max_depth=3)
    assert prop.origin_id == "url-1"
    assert prop.impacted_count >= 1
    assert prop.threat_count >= 1  # a threat node hangs off url-1


def test_shared_infrastructure_detects_shared_ioc() -> None:
    svc = _analytics()
    shared = svc.shared_infrastructure("url-1", top=5)
    assert shared
    peer = shared[0]
    assert peer.origin_id == "url-1"
    assert "ioc-9" in peer.shared_ids
    assert peer.shared_count >= 1


def test_neighborhood_and_attack_paths() -> None:
    svc = _analytics()
    hood = svc.neighborhood("url-1", hops=2)
    assert hood.node_count >= 1
    assert hood.edge_count >= 0
    paths = svc.shortest_attack_paths("file-1", "url-1")
    # file-1 and url-1 are connected via the shared IOC node.
    assert all(p.hops >= 0 for p in paths)


def test_report_and_metrics() -> None:
    svc = _analytics()
    report = svc.report(top=3)
    assert report.node_count >= 1
    assert report.top_degree
    assert report.components.component_count >= 1
    metrics = svc.metrics()
    assert metrics["runs"] >= 1.0
    assert metrics["total_ms"] >= 0.0


def test_empty_graph_is_safe() -> None:
    svc = GraphAnalyticsService(GraphQueryService(InMemoryGraphRepository()), _FakeLogger())
    assert svc.degree_ranking() == ()
    assert svc.component_analysis().component_count == 0
    assert svc.relationship_density() == 0.0
    assert svc.blast_radius("ghost").reachable_count == 0
    assert svc.threat_propagation("ghost").threat_count == 0

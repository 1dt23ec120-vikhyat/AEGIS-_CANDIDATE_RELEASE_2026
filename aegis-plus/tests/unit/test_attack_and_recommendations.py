"""Tests for the Attack Analysis (Phase C) and Recommendation (Phase D) engines."""

from __future__ import annotations

from core.domain.events import (
    artifact_analyzed,
    campaign_created,
    incident_created,
    relationship_discovered,
    threat_recorded,
)
from infrastructure.graph import InMemoryGraphRepository
from services.analytics import (
    AttackAnalysisService,
    CampaignIntelligenceService,
    GraphAnalyticsService,
    IOCIntelligenceService,
    RecommendationService,
    ThreatScoringService,
)
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


def _query() -> GraphQueryService:
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
            verdict="malicious",
            risk_score=0.8,
            category="malware",
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
    return GraphQueryService(repo)


def _attack(query: GraphQueryService) -> AttackAnalysisService:
    return AttackAnalysisService(query, GraphAnalyticsService(query, _FakeLogger()), _FakeLogger())


# --- Phase C: attack analysis ------------------------------------------


def test_attack_chain_reconstruction() -> None:
    svc = _attack(_query())
    chain = svc.attack_chain("file-1", "url-1")
    # file-1 -> ioc-9 -> url-1 is the shortest chain via the shared IOC.
    assert chain.length >= 2
    assert chain.steps[0].order == 0
    assert all(step.kill_chain_phase for step in chain.steps)
    assert chain.rationale


def test_kill_chain_mapping_groups_phases() -> None:
    svc = _attack(_query())
    mapping = svc.kill_chain_mapping("url-1", max_depth=4)
    phases = dict(mapping.phases)
    # url-1 is a delivery-phase node; the shared IOC is C2.
    assert "delivery" in phases
    assert "command_and_control" in phases
    assert mapping.rationale


def test_compromise_paths() -> None:
    svc = _attack(_query())
    paths = svc.compromise_paths("file-1", "url-1")
    assert all(p.hops >= 0 for p in paths)
    for p in paths:
        assert p.rationale


def test_root_cause_analysis() -> None:
    svc = _attack(_query())
    cause = svc.root_cause("inc-1", max_depth=4)
    assert cause.incident_id == "inc-1"
    assert cause.root_id  # an artifact was identified
    assert cause.root_type in {"url", "file", "email", "artifact"}
    assert cause.evidence_ids
    assert cause.rationale


def test_infrastructure_clusters() -> None:
    svc = _attack(_query())
    clusters = svc.infrastructure_clusters(top=5)
    assert clusters
    top = clusters[0]
    assert top.infra_id == "ioc-9"
    assert top.size >= 2
    assert "url-1" in top.member_ids and "file-1" in top.member_ids


def test_attack_timeline_is_ordered() -> None:
    svc = _attack(_query())
    timeline = svc.attack_timeline("url-1", max_depth=4)
    stamps = [e.timestamp for e in timeline.entries]
    assert stamps == sorted(stamps)
    assert timeline.rationale


def test_threat_propagation_reuses_analytics() -> None:
    svc = _attack(_query())
    prop = svc.threat_propagation("url-1", max_depth=4)
    assert prop.origin_id == "url-1"
    assert prop.threat_count >= 1


# --- Phase D: recommendations ------------------------------------------


def _recommender(query: GraphQueryService) -> RecommendationService:
    analytics = GraphAnalyticsService(query, _FakeLogger())
    return RecommendationService(
        analytics,
        IOCIntelligenceService(query, _FakeLogger()),
        CampaignIntelligenceService(query, _FakeLogger()),
        ThreatScoringService(query, analytics, _FakeLogger()),
        _FakeLogger(),
    )


def test_next_investigation_and_ioc_recommendations() -> None:
    svc = _recommender(_query())
    nxt = svc.next_investigation()
    assert nxt is not None
    assert nxt.kind == "next_investigation"
    assert nxt.subject_id
    assert nxt.rationale  # WHY
    ioc = svc.highest_priority_ioc()
    assert ioc is not None
    assert ioc.subject_type == "ioc"
    assert ioc.rationale


def test_campaign_and_relationship_recommendations() -> None:
    svc = _recommender(_query())
    camp = svc.highest_risk_campaign()
    assert camp is not None
    assert camp.subject_type == "campaign"
    rel = svc.most_suspicious_relationship()
    assert rel is not None  # ioc-9 is reused across 2 artifacts
    assert "reused" in " ".join(rel.rationale).lower()


def test_containment_and_sequence_are_ordered() -> None:
    svc = _recommender(_query())
    containment = svc.containment_order(top=5)
    assert containment
    exposures = [r.priority for r in containment]
    assert exposures == sorted(exposures, reverse=True)
    sequence = svc.investigation_sequence(top=5)
    urgencies = [r.priority for r in sequence]
    assert urgencies == sorted(urgencies, reverse=True)


def test_recommended_actions_aggregate() -> None:
    svc = _recommender(_query())
    actions = svc.recommended_actions()
    assert actions.count >= 1
    priorities = [r.priority for r in actions.recommendations]
    assert priorities == sorted(priorities, reverse=True)
    assert svc.metrics()["runs"] >= 1.0


def test_empty_graph_recommendations_are_safe() -> None:
    svc = _recommender(GraphQueryService(InMemoryGraphRepository()))
    assert svc.next_investigation() is None
    assert svc.highest_priority_ioc() is None
    assert svc.recommended_actions().count == 0

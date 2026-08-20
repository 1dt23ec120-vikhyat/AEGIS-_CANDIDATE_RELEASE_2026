"""Tests for the Threat Intelligence Engine (M11 Phase B)."""

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
    CampaignIntelligenceService,
    GraphAnalyticsService,
    IOCIntelligenceService,
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
    # Two malicious artifacts sharing an IOC, plus a campaign and threat.
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
        bus.publish(
            relationship_discovered(
                source="c",
                source_id="camp-1",
                source_type="campaign",
                target_id=artifact,
                target_type=atype,
                relationship="associated_with",
            )
        )
    return GraphQueryService(repo)


# --- IOC intelligence ---------------------------------------------------


def test_ioc_intelligence_frequency_and_confidence() -> None:
    svc = IOCIntelligenceService(_query(), _FakeLogger())
    intel = svc.analyze("ioc-9")
    assert intel.ioc_id == "ioc-9"
    assert intel.frequency >= 2  # shared by url-1 and file-1
    assert intel.reuse_count == intel.frequency
    assert 0.0 <= intel.confidence <= 1.0
    assert 0.0 <= intel.prevalence <= 1.0
    assert intel.rationale  # explainability


def test_ioc_ranking_is_deterministic() -> None:
    svc = IOCIntelligenceService(_query(), _FakeLogger())
    assert svc.rank(top=5) == svc.rank(top=5)
    ranked = svc.rank(top=5)
    assert ranked
    confidences = [i.confidence for i in ranked]
    assert confidences == sorted(confidences, reverse=True)


# --- campaign intelligence ---------------------------------------------


def test_campaign_intelligence_counts() -> None:
    svc = CampaignIntelligenceService(_query(), _FakeLogger())
    intel = svc.analyze("camp-1")
    assert intel.campaign_id == "camp-1"
    assert intel.artifact_count >= 2
    assert intel.ioc_count >= 1
    assert intel.rationale


def test_campaign_similarity_self_is_total() -> None:
    svc = CampaignIntelligenceService(_query(), _FakeLogger())
    sim = svc.similarity("camp-1", "camp-1")
    # A campaign is identical to itself: Jaccard 1.0 when it has infrastructure.
    assert sim.similarity == 1.0
    assert sim.shared_infrastructure >= 1


# --- threat scoring -----------------------------------------------------


def test_threat_score_is_explainable_and_bounded() -> None:
    query = _query()
    analytics = GraphAnalyticsService(query, _FakeLogger())
    svc = ThreatScoringService(query, analytics, _FakeLogger())
    score = svc.score("url-1")
    assert score.artifact_id == "url-1"
    for value in (
        score.severity,
        score.confidence,
        score.exposure,
        score.priority,
        score.analyst_urgency,
    ):
        assert 0.0 <= value <= 1.0
    assert score.blast_radius >= 1
    assert score.severity > 0.0  # url-1 has risk 0.9
    assert len(score.rationale) >= 3


def test_threat_ranking_orders_by_urgency() -> None:
    query = _query()
    analytics = GraphAnalyticsService(query, _FakeLogger())
    svc = ThreatScoringService(query, analytics, _FakeLogger())
    ranked = svc.rank(top=10)
    assert ranked
    urgencies = [s.analyst_urgency for s in ranked]
    assert urgencies == sorted(urgencies, reverse=True)
    # The high-risk phishing URL should outrank a benign artifact.
    assert ranked[0].severity >= ranked[-1].severity


def test_metrics_exposed() -> None:
    svc = IOCIntelligenceService(_query(), _FakeLogger())
    svc.analyze("ioc-9")
    metrics = svc.metrics()
    assert metrics["runs"] >= 1.0
    assert "op.analyze" in metrics

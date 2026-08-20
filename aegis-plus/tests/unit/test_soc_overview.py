"""Tests for the SOC command centre aggregation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any

from core.constants import IncidentStatus, InvestigationPriority
from core.domain.analysis import Verdict
from core.domain.correlation import ArtifactKind, ArtifactRef
from core.domain.intelligence import ThreatCategory
from core.entities import Campaign, EmailScan, Incident, ThreatEntry, UrlScan
from core.interfaces import IUnitOfWork
from infrastructure.logging import get_logger
from services.soc import HealthComponent, SocOverviewService


class _Repo:
    def __init__(self, items: list[Any]) -> None:
        self._items = items

    def list(self) -> list[Any]:
        return list(self._items)


class _Uow(IUnitOfWork):
    def __init__(self, store: dict[Any, list[Any]]) -> None:
        self._store = store

    def __enter__(self) -> IUnitOfWork:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def get_repository(self, entity_type: type[Any]) -> Any:
        return _Repo(self._store.get(entity_type, []))


def _incident(
    *,
    risk: float = 0.9,
    status: IncidentStatus = IncidentStatus.OPEN,
    assignee: str = "",
    users: tuple[str, ...] = ("one@corp.com",),
) -> Incident:
    return Incident(
        title="Test incident",
        category=ThreatCategory.PHISHING,
        risk_score=risk,
        status=status,
        priority=InvestigationPriority.HIGH,
        assignee=assignee,
        artifacts=(ArtifactRef(ArtifactKind.SENDER, "a@b.com"),),
        scan_ids=("s1",),
        affected_users=users,
    )


def _campaign(*, occurrences: int = 2, risk: float = 0.9) -> Campaign:
    return Campaign(
        name="Test campaign",
        category=ThreatCategory.PHISHING,
        risk_score=risk,
        occurrences=occurrences,
        affected_users=("one@corp.com", "two@corp.com"),
    )


def _email_scan(verdict: Verdict = Verdict.PHISHING, score: float = 0.9) -> EmailScan:
    return EmailScan(
        sender="bad@evil.xyz",
        subject="Urgent",
        verdict=verdict,
        threat_score=score,
        confidence=0.8,
        category=ThreatCategory.CREDENTIAL_HARVESTING,
        evidence_strength=0.6,
        contributions=(),
        sources=(),
    )


def _url_scan(
    verdict: Verdict = Verdict.PHISHING,
    score: float = 0.95,
    created_at: datetime | None = None,
) -> UrlScan:
    return UrlScan(
        url="http://evil.example/login",
        verdict=verdict,
        threat_score=score,
        confidence=0.9,
        contributions=(),
        features={},
        created_at=created_at,
    )


def _threat() -> ThreatEntry:
    now = datetime.now(UTC)
    return ThreatEntry(
        artifact_hash="h" * 64,
        artifact="http://evil.example/login",
        verdict=Verdict.PHISHING,
        risk_score=0.95,
        confidence=0.9,
        indicators=(),
        first_detected=now,
        last_detected=now,
    )


def _service(store: dict[Any, list[Any]], *, healthy: bool = True) -> SocOverviewService:
    def health() -> tuple[HealthComponent, ...]:
        status = "healthy" if healthy else "unhealthy"
        return (HealthComponent(name="database", status=status, detail="ok"),)

    return SocOverviewService(lambda: _Uow(store), health, get_logger("test-soc"))


def test_empty_platform_reports_normal_posture() -> None:
    overview = _service({}).overview()
    assert overview.threat_level == "Normal"
    assert overview.risk_score == 0.0
    assert overview.platform_status == "Operational"
    assert overview.incident_queue == ()
    assert overview.timeline == ()


def test_open_critical_incident_raises_threat_level() -> None:
    """A single severe open incident must not be under-reported."""
    overview = _service({Incident: [_incident(risk=0.95)]}).overview()
    assert overview.threat_level == "Critical"
    assert overview.risk_score >= 0.95
    assert len(overview.incident_queue) == 1


def test_posture_never_falls_below_worst_open_incident() -> None:
    overview = _service({Incident: [_incident(risk=0.62)]}).overview()
    assert overview.risk_score >= 0.62


def test_resolved_incidents_do_not_drive_threat_level() -> None:
    store: dict[Any, list[Any]] = {Incident: [_incident(risk=0.95, status=IncidentStatus.RESOLVED)]}
    overview = _service(store).overview()
    assert overview.threat_level == "Normal"
    assert overview.incident_queue == ()


def test_unhealthy_component_degrades_platform_status() -> None:
    overview = _service({}, healthy=False).overview()
    assert overview.platform_status == "Degraded"


def test_timeline_merges_and_orders_all_sources() -> None:
    store: dict[Any, list[Any]] = {
        Incident: [_incident()],
        Campaign: [_campaign()],
        ThreatEntry: [_threat()],
        EmailScan: [_email_scan()],
        UrlScan: [_url_scan()],
    }
    overview = _service(store).overview()
    kinds = {e.kind for e in overview.timeline}
    assert "url_analysis" in kinds
    assert "email_analysis" in kinds
    assert "threat_blocked" in kinds
    assert "campaign_created" in kinds
    timestamps = [e.occurred_at for e in overview.timeline]
    assert timestamps == sorted(timestamps, reverse=True)


def test_threat_and_analytics_metrics_are_derived() -> None:
    store: dict[Any, list[Any]] = {
        EmailScan: [_email_scan(), _email_scan(Verdict.LEGITIMATE, 0.0)],
        UrlScan: [_url_scan()],
        ThreatEntry: [_threat()],
    }
    overview = _service(store).overview()
    analytics = {m.label: m.value for m in overview.analytics}
    assert analytics["Artifacts analyzed"] == "3"
    assert analytics["Detections"] == "2"
    assert analytics["Detection rate"] == "67%"
    senders = dict(overview.top_malicious_senders)
    assert senders["bad@evil.xyz"] == 1
    assert dict(overview.risk_distribution)["Critical"] == 2


def test_campaign_metrics_identify_notable_campaigns() -> None:
    store: dict[Any, list[Any]] = {
        Campaign: [_campaign(occurrences=5, risk=0.6), _campaign(occurrences=2, risk=0.99)]
    }
    overview = _service(store).overview()
    metrics = {m.label: m for m in overview.campaign_metrics}
    assert metrics["Active campaigns"].value == "2"
    assert metrics["Most dangerous"].detail == "99% risk"
    assert metrics["Largest"].detail == "5 detections"


def test_analyst_activity_reflects_assignment() -> None:
    store: dict[Any, list[Any]] = {
        Incident: [
            _incident(assignee="alice"),
            _incident(assignee=""),
            _incident(assignee="alice", status=IncidentStatus.RESOLVED),
        ]
    }
    overview = _service(store).overview()
    activity = {m.label: m.value for m in overview.analyst_activity}
    assert activity["Assigned incidents"] == "2"
    assert activity["Unassigned"] == "1"
    assert activity["Resolved cases"] == "1"
    assert activity["Busiest analyst"] == "alice"


def test_detection_trend_covers_seven_days() -> None:
    overview = _service({UrlScan: [_url_scan()]}).overview()
    assert len(overview.detection_trend) == 7
    assert overview.detection_trend[-1][1] == 1


def test_affected_users_are_deduplicated_across_incidents() -> None:
    store: dict[Any, list[Any]] = {
        Incident: [
            _incident(users=("one@corp.com", "two@corp.com")),
            _incident(users=("two@corp.com", "three@corp.com")),
        ]
    }
    overview = _service(store).overview()
    metrics = {m.label: m.value for m in overview.incident_metrics}
    assert metrics["Affected users"] == "3"


def test_snapshot_is_loaded_once_per_overview() -> None:
    """The whole dashboard must cost one pass over each repository."""
    calls: list[type] = []

    class _CountingUow(_Uow):
        def get_repository(self, entity_type: type[Any]) -> Any:
            calls.append(entity_type)
            return _Repo([])

    service = SocOverviewService(
        lambda: _CountingUow({}),
        lambda: (),
        get_logger("test-soc"),
    )
    service.overview()
    assert len(calls) == len(set(calls))


def test_containment_and_response_report_not_available_when_empty() -> None:
    overview = _service({Incident: [_incident()]}).overview()
    analytics = {m.label: m.value for m in overview.analytics}
    assert analytics["Avg response"] == "n/a"
    assert analytics["Containment"] == "n/a"


def test_false_positive_rate_is_reported() -> None:
    store: dict[Any, list[Any]] = {
        Incident: [
            _incident(status=IncidentStatus.FALSE_POSITIVE),
            _incident(),
        ]
    }
    overview = _service(store).overview()
    analytics = {m.label: m.value for m in overview.analytics}
    assert analytics["False positives"] == "50%"


def test_recent_incident_updates_are_timestamped() -> None:
    incident = _incident()
    incident.add_comment(author="alice", body="Looks like a wave")
    overview = _service({Incident: [incident]}).overview()
    assert overview.recent_comments[0] == ("alice", "Looks like a wave")
    assert any(e.title == "Comment added" for e in overview.timeline)


def test_old_scans_excluded_from_last_24h_window() -> None:
    old = _url_scan(created_at=datetime.now(UTC) - timedelta(days=3))
    overview = _service({UrlScan: [old, _url_scan()]}).overview()
    analytics = {m.label: m.value for m in overview.analytics}
    assert analytics["Last 24h"] == "1"
    assert analytics["Last 7d"] == "2"

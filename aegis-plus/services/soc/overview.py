"""SOC command centre aggregation.

Builds the operational picture the command centre renders. It consumes existing
platform state only - URL scans, email scans, threat intelligence, incidents,
campaigns, and health checks - and adds no detection logic of its own.

Every metric is derived from a single snapshot loaded in one Unit of Work, so
rendering the whole dashboard costs one pass over each repository rather than one
query per widget. New intelligence verticals (file, IP, domain, endpoint) surface
here by contributing to the same snapshot; the aggregation shape does not change.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from core.constants import ArtifactType, IncidentStatus
from core.domain.analysis import Verdict
from core.entities import (
    Campaign,
    EmailScan,
    FileScan,
    Incident,
    ThreatEntry,
    UrlScan,
)
from core.interfaces import ILogger, IUnitOfWork

_CRITICAL_RISK = 0.8
_ELEVATED_RISK = 0.5
_TOP_N = 5
_TIMELINE_LIMIT = 40
_TREND_DAYS = 7
_PRESSURE_WEIGHT = 0.2


@dataclass(frozen=True, slots=True)
class MetricCard:
    """A single labelled metric with optional trend context."""

    label: str
    value: str
    detail: str = ""
    tone: str = "neutral"


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    """One entry in the unified SOC timeline."""

    occurred_at: datetime
    kind: str
    severity: str
    title: str
    detail: str
    artifact_type: str = ""
    incident_id: str = ""
    campaign_id: str = ""

    @property
    def timestamp(self) -> str:
        """An ISO-8601 timestamp for transport."""
        return self.occurred_at.isoformat()


@dataclass(frozen=True, slots=True)
class IncidentSummary:
    """A compact incident row for the queue."""

    id: str
    title: str
    category: str
    risk_percent: int
    status: str
    priority: str
    assignee: str
    occurrences: int
    affected_users: int
    last_seen: str


@dataclass(frozen=True, slots=True)
class CampaignSummary:
    """A compact campaign card."""

    id: str
    name: str
    category: str
    risk_percent: int
    occurrences: int
    affected_users: int
    first_seen: str
    last_seen: str


@dataclass(frozen=True, slots=True)
class HealthComponent:
    """One platform component's health."""

    name: str
    status: str
    detail: str


@dataclass(frozen=True, slots=True)
class SocOverview:
    """The complete operational picture."""

    threat_level: str
    risk_score: float
    platform_status: str
    generated_at: str
    posture: tuple[MetricCard, ...] = ()
    incident_metrics: tuple[MetricCard, ...] = ()
    incident_queue: tuple[IncidentSummary, ...] = ()
    priority_distribution: tuple[tuple[str, int], ...] = ()
    campaign_metrics: tuple[MetricCard, ...] = ()
    campaigns: tuple[CampaignSummary, ...] = ()
    threat_metrics: tuple[MetricCard, ...] = ()
    top_malicious_urls: tuple[tuple[str, int], ...] = ()
    top_malicious_senders: tuple[tuple[str, int], ...] = ()
    threat_categories: tuple[tuple[str, int], ...] = ()
    artifact_distribution: tuple[tuple[str, int], ...] = ()
    timeline: tuple[TimelineEvent, ...] = ()
    analytics: tuple[MetricCard, ...] = ()
    risk_distribution: tuple[tuple[str, int], ...] = ()
    detection_trend: tuple[tuple[str, int], ...] = ()
    analyst_activity: tuple[MetricCard, ...] = ()
    recent_comments: tuple[tuple[str, str], ...] = ()
    health: tuple[HealthComponent, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class _Snapshot:
    """Everything loaded in one pass."""

    incidents: list[Incident]
    campaigns: list[Campaign]
    threats: list[ThreatEntry]
    email_scans: list[EmailScan]
    url_scans: list[UrlScan]
    file_scans: list[FileScan]


class SocOverviewService:
    """Aggregates platform state into the SOC command centre overview."""

    def __init__(
        self,
        unit_of_work_factory: Callable[[], IUnitOfWork],
        health: Callable[[], tuple[HealthComponent, ...]],
        logger: ILogger,
    ) -> None:
        """Initialize the service.

        Args:
            unit_of_work_factory: Produces a Unit of Work for the snapshot load.
            health: Supplies current platform component health.
            logger: Injected logger.
        """
        self._unit_of_work_factory = unit_of_work_factory
        self._health = health
        self._logger = logger

    def overview(self) -> SocOverview:
        """Build the complete operational picture from one snapshot."""
        snapshot = self._load()
        now = datetime.now(UTC)

        open_incidents = [i for i in snapshot.incidents if i.is_open]
        critical = [i for i in open_incidents if i.risk_score >= _CRITICAL_RISK]
        investigating = [i for i in snapshot.incidents if i.status is IncidentStatus.INVESTIGATING]
        resolved_today = [
            i
            for i in snapshot.incidents
            if not i.is_open and self._utc(i.updated_at).date() == now.date()
        ]
        blocked = [t for t in snapshot.threats if t.blocked]
        malicious_emails = [s for s in snapshot.email_scans if s.verdict is Verdict.PHISHING]
        malicious_urls = [s for s in snapshot.url_scans if s.verdict is Verdict.PHISHING]
        malicious_files = [s for s in snapshot.file_scans if s.verdict is Verdict.PHISHING]
        all_hashes = {s.sha256 for s in snapshot.file_scans if s.verdict is Verdict.PHISHING}
        unique_malicious_hashes = len(all_hashes)

        risk_score = self._risk_score(open_incidents, critical)
        threat_level = self._threat_level(risk_score)
        health = self._health()
        platform_status = (
            "Operational" if all(c.status == "healthy" for c in health) else "Degraded"
        )

        overview = SocOverview(
            threat_level=threat_level,
            risk_score=round(risk_score, 4),
            platform_status=platform_status,
            generated_at=now.isoformat(),
            posture=(
                MetricCard("Threat level", threat_level, tone=self._tone(risk_score)),
                MetricCard(
                    "Overall risk", f"{round(risk_score * 100)}%", tone=self._tone(risk_score)
                ),
                MetricCard(
                    "Open incidents",
                    str(len(open_incidents)),
                    tone="danger" if open_incidents else "success",
                ),
                MetricCard(
                    "Active campaigns",
                    str(len(snapshot.campaigns)),
                    tone="warning" if snapshot.campaigns else "success",
                ),
                MetricCard("Threat intelligence hits", str(len(snapshot.threats))),
                MetricCard("Blocked threats", str(len(blocked)), tone="success"),
                MetricCard(
                    "Critical alerts", str(len(critical)), tone="danger" if critical else "success"
                ),
                MetricCard(
                    "Platform",
                    platform_status,
                    tone="success" if platform_status == "Operational" else "warning",
                ),
            ),
            incident_metrics=(
                MetricCard("Open", str(len(open_incidents))),
                MetricCard("Critical", str(len(critical)), tone="danger"),
                MetricCard("Investigating", str(len(investigating)), tone="warning"),
                MetricCard("Resolved today", str(len(resolved_today)), tone="success"),
                MetricCard(
                    "Affected users",
                    str(len({u for i in snapshot.incidents for u in i.affected_users})),
                ),
                MetricCard("Avg response", self._avg_response(snapshot.incidents)),
            ),
            incident_queue=tuple(
                self._incident_summary(i)
                for i in sorted(open_incidents, key=lambda i: i.risk_score, reverse=True)[:_TOP_N]
            ),
            priority_distribution=self._counter(i.priority.value for i in open_incidents),
            campaign_metrics=self._campaign_metrics(snapshot.campaigns),
            campaigns=tuple(
                self._campaign_summary(c)
                for c in sorted(snapshot.campaigns, key=lambda c: c.occurrences, reverse=True)[
                    :_TOP_N
                ]
            ),
            threat_metrics=(
                MetricCard("Blacklisted artifacts", str(len(snapshot.threats))),
                MetricCard("Blocked", str(len(blocked)), tone="success"),
                MetricCard(
                    "High risk",
                    str(sum(1 for t in snapshot.threats if t.risk_score >= _CRITICAL_RISK)),
                    tone="danger",
                ),
                MetricCard("Malicious emails", str(len(malicious_emails))),
                MetricCard("Malicious URLs", str(len(malicious_urls))),
                MetricCard("Malicious files", str(len(malicious_files))),
                MetricCard("Malicious hashes", str(unique_malicious_hashes)),
                MetricCard("Recent uploads", str(len(snapshot.file_scans))),
            ),
            top_malicious_urls=self._counter(s.url for s in malicious_urls),
            top_malicious_senders=self._counter(s.sender for s in malicious_emails),
            threat_categories=self._counter(
                s.category.value
                for s in snapshot.email_scans
                if s.verdict is not Verdict.LEGITIMATE
            ),
            artifact_distribution=self._counter(t.artifact_type.value for t in snapshot.threats),
            timeline=self._timeline(snapshot),
            analytics=self._analytics(snapshot, now),
            risk_distribution=self._risk_distribution(snapshot),
            detection_trend=self._detection_trend(snapshot, now),
            analyst_activity=self._analyst_activity(snapshot.incidents),
            recent_comments=tuple(
                (c.author, c.body)
                for incident in sorted(
                    snapshot.incidents, key=lambda i: self._utc(i.updated_at), reverse=True
                )
                for c in incident.comments
            )[:_TOP_N],
            health=health,
        )
        self._logger.info(
            "SOC overview built: {} open incident(s), {} campaign(s), threat level {}",
            len(open_incidents),
            len(snapshot.campaigns),
            threat_level,
        )
        return overview

    # --- loading --------------------------------------------------------

    def _load(self) -> _Snapshot:
        with self._unit_of_work_factory() as uow:
            return _Snapshot(
                incidents=uow.get_repository(Incident).list(),
                campaigns=uow.get_repository(Campaign).list(),
                threats=uow.get_repository(ThreatEntry).list(),
                email_scans=uow.get_repository(EmailScan).list(),
                url_scans=uow.get_repository(UrlScan).list(),
                file_scans=uow.get_repository(FileScan).list(),
            )

    # --- derivations ----------------------------------------------------

    @staticmethod
    def _utc(value: datetime) -> datetime:
        """Return ``value`` as timezone-aware UTC.

        SQLite does not preserve tzinfo, so timestamps read back from the
        database are naive. Every comparison and sort in this aggregation mixes
        stored timestamps with the current time, so they are normalized here
        rather than at each call site.
        """
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    @staticmethod
    def _risk_score(open_incidents: list[Incident], critical: list[Incident]) -> float:
        """Overall posture: never below the worst open incident, raised by volume.

        Posture must not under-report a single severe incident, so the peak open
        risk is a floor. A growing number of critical incidents adds pressure on
        top of that floor, capped at 1.0.
        """
        if not open_incidents:
            return 0.0
        peak = max(i.risk_score for i in open_incidents)
        pressure = min(len(critical) / _TOP_N, 1.0)
        return min(peak + _PRESSURE_WEIGHT * pressure, 1.0)

    @staticmethod
    def _threat_level(risk_score: float) -> str:
        if risk_score >= _CRITICAL_RISK:
            return "Critical"
        if risk_score >= _ELEVATED_RISK:
            return "Elevated"
        if risk_score > 0:
            return "Guarded"
        return "Normal"

    @staticmethod
    def _tone(risk_score: float) -> str:
        if risk_score >= _CRITICAL_RISK:
            return "danger"
        if risk_score >= _ELEVATED_RISK:
            return "warning"
        return "success"

    @staticmethod
    def _counter(values: Iterable[str]) -> tuple[tuple[str, int], ...]:
        return tuple(Counter(values).most_common(_TOP_N))

    @classmethod
    def _avg_response(cls, incidents: list[Incident]) -> str:
        deltas = [
            (cls._utc(i.updated_at) - cls._utc(i.created_at)).total_seconds()
            for i in incidents
            if i.status is not IncidentStatus.OPEN
        ]
        if not deltas:
            return "n/a"
        minutes = sum(deltas) / len(deltas) / 60
        return f"{minutes:.1f} min"

    @staticmethod
    def _incident_summary(incident: Incident) -> IncidentSummary:
        return IncidentSummary(
            id=str(incident.id),
            title=incident.title,
            category=incident.category.value,
            risk_percent=incident.risk_percent,
            status=incident.status.value,
            priority=incident.priority.value,
            assignee=incident.assignee,
            occurrences=incident.occurrences,
            affected_users=len(incident.affected_users),
            last_seen=incident.last_seen.isoformat(),
        )

    @staticmethod
    def _campaign_summary(campaign: Campaign) -> CampaignSummary:
        return CampaignSummary(
            id=str(campaign.id),
            name=campaign.name,
            category=campaign.category.value,
            risk_percent=campaign.risk_percent,
            occurrences=campaign.occurrences,
            affected_users=len(campaign.affected_users),
            first_seen=campaign.first_seen.isoformat(),
            last_seen=campaign.last_seen.isoformat(),
        )

    def _campaign_metrics(self, campaigns: list[Campaign]) -> tuple[MetricCard, ...]:
        if not campaigns:
            return (MetricCard("Active campaigns", "0", tone="success"),)
        dangerous = max(campaigns, key=lambda c: c.risk_score)
        largest = max(campaigns, key=lambda c: c.occurrences)
        newest = max(campaigns, key=lambda c: self._utc(c.first_seen))
        return (
            MetricCard("Active campaigns", str(len(campaigns)), tone="warning"),
            MetricCard(
                "Most dangerous",
                dangerous.name,
                f"{dangerous.risk_percent}% risk",
                tone="danger",
            ),
            MetricCard(
                "Largest",
                largest.name,
                f"{largest.occurrences} detections",
                tone="warning",
            ),
            MetricCard("Newest", newest.name, self._utc(newest.first_seen).strftime("%H:%M")),
            MetricCard(
                "Users affected",
                str(len({u for c in campaigns for u in c.affected_users})),
            ),
        )

    def _timeline(self, snapshot: _Snapshot) -> tuple[TimelineEvent, ...]:
        events: list[TimelineEvent] = []
        for url_scan in snapshot.url_scans:
            events.append(
                TimelineEvent(
                    occurred_at=self._utc(url_scan.created_at),
                    kind="url_analysis",
                    severity=self._severity(url_scan.threat_score),
                    title="URL analyzed",
                    detail=f"{url_scan.url} ({url_scan.verdict.value})",
                    artifact_type=ArtifactType.URL.value,
                )
            )
        for email_scan in snapshot.email_scans:
            events.append(
                TimelineEvent(
                    occurred_at=self._utc(email_scan.created_at),
                    kind="email_analysis",
                    severity=self._severity(email_scan.threat_score),
                    title="Email analyzed",
                    detail=(
                        f"{email_scan.sender} - {email_scan.subject} "
                        f"({email_scan.verdict.value})"
                    ),
                    artifact_type=ArtifactType.EMAIL.value,
                )
            )
        for threat in snapshot.threats:
            events.append(
                TimelineEvent(
                    occurred_at=self._utc(threat.first_detected),
                    kind="threat_blocked",
                    severity=self._severity(threat.risk_score),
                    title="Threat blocked",
                    detail=threat.artifact,
                    artifact_type=threat.artifact_type.value,
                )
            )
        for campaign in snapshot.campaigns:
            events.append(
                TimelineEvent(
                    occurred_at=self._utc(campaign.first_seen),
                    kind="campaign_created",
                    severity=self._severity(campaign.risk_score),
                    title="Campaign discovered",
                    detail=campaign.name,
                    campaign_id=str(campaign.id),
                )
            )
        for incident in snapshot.incidents:
            for event in incident.events:
                events.append(
                    TimelineEvent(
                        occurred_at=self._utc(event.occurred_at),
                        kind=event.label.lower().replace(" ", "_"),
                        severity=self._severity(incident.risk_score),
                        title=event.label,
                        detail=f"{incident.title}: {event.detail}",
                        incident_id=str(incident.id),
                        campaign_id=incident.campaign_id,
                    )
                )
        events.sort(key=lambda e: e.occurred_at, reverse=True)
        return tuple(events[:_TIMELINE_LIMIT])

    @staticmethod
    def _severity(risk: float) -> str:
        if risk >= _CRITICAL_RISK:
            return "critical"
        if risk >= _ELEVATED_RISK:
            return "high"
        if risk > 0:
            return "medium"
        return "info"

    def _analytics(self, snapshot: _Snapshot, now: datetime) -> tuple[MetricCard, ...]:
        total = len(snapshot.url_scans) + len(snapshot.email_scans) + len(snapshot.file_scans)
        detections = (
            sum(1 for s in snapshot.url_scans if s.verdict is not Verdict.LEGITIMATE)
            + sum(1 for s in snapshot.email_scans if s.verdict is not Verdict.LEGITIMATE)
            + sum(1 for s in snapshot.file_scans if s.verdict is not Verdict.LEGITIMATE)
        )
        day = self._since(snapshot, now - timedelta(days=1))
        week = self._since(snapshot, now - timedelta(days=7))
        month = self._since(snapshot, now - timedelta(days=30))
        rate = f"{round(detections / total * 100)}%" if total else "n/a"
        return (
            MetricCard("Artifacts analyzed", str(total)),
            MetricCard("Detections", str(detections), tone="danger"),
            MetricCard("Detection rate", rate),
            MetricCard("Last 24h", str(day)),
            MetricCard("Last 7d", str(week)),
            MetricCard("Last 30d", str(month)),
            MetricCard("Avg response", self._avg_response(snapshot.incidents)),
            MetricCard("Containment", self._containment(snapshot.incidents)),
            MetricCard("False positives", self._false_positive_rate(snapshot.incidents)),
        )

    @classmethod
    def _since(cls, snapshot: _Snapshot, cutoff: datetime) -> int:
        return (
            sum(1 for s in snapshot.url_scans if cls._utc(s.created_at) >= cutoff)
            + sum(1 for s in snapshot.email_scans if cls._utc(s.created_at) >= cutoff)
            + sum(1 for s in snapshot.file_scans if cls._utc(s.created_at) >= cutoff)
        )

    @classmethod
    def _containment(cls, incidents: list[Incident]) -> str:
        contained = [
            i for i in incidents if i.status in (IncidentStatus.CONTAINED, IncidentStatus.RESOLVED)
        ]
        if not contained:
            return "n/a"
        minutes = (
            sum(
                (cls._utc(i.updated_at) - cls._utc(i.created_at)).total_seconds() for i in contained
            )
            / len(contained)
            / 60
        )
        return f"{minutes:.1f} min"

    @staticmethod
    def _false_positive_rate(incidents: list[Incident]) -> str:
        if not incidents:
            return "n/a"
        false_positives = sum(1 for i in incidents if i.status is IncidentStatus.FALSE_POSITIVE)
        return f"{round(false_positives / len(incidents) * 100)}%"

    def _risk_distribution(self, snapshot: _Snapshot) -> tuple[tuple[str, int], ...]:
        buckets = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        scores = (
            [s.threat_score for s in snapshot.url_scans]
            + [s.threat_score for s in snapshot.email_scans]
            + [s.threat_score for s in snapshot.file_scans]
        )
        for score in scores:
            if score >= _CRITICAL_RISK:
                buckets["Critical"] += 1
            elif score >= _ELEVATED_RISK:
                buckets["High"] += 1
            elif score > 0:
                buckets["Medium"] += 1
            else:
                buckets["Low"] += 1
        return tuple(buckets.items())

    @classmethod
    def _detection_trend(cls, snapshot: _Snapshot, now: datetime) -> tuple[tuple[str, int], ...]:
        trend: list[tuple[str, int]] = []
        for offset in range(_TREND_DAYS - 1, -1, -1):
            day = (now - timedelta(days=offset)).date()
            count = (
                sum(
                    1
                    for s in snapshot.url_scans
                    if cls._utc(s.created_at).date() == day and s.verdict is not Verdict.LEGITIMATE
                )
                + sum(
                    1
                    for s in snapshot.email_scans
                    if cls._utc(s.created_at).date() == day and s.verdict is not Verdict.LEGITIMATE
                )
                + sum(
                    1
                    for s in snapshot.file_scans
                    if cls._utc(s.created_at).date() == day and s.verdict is not Verdict.LEGITIMATE
                )
            )
            trend.append((day.strftime("%d %b"), count))
        return tuple(trend)

    @staticmethod
    def _analyst_activity(incidents: list[Incident]) -> tuple[MetricCard, ...]:
        assigned = [i for i in incidents if i.assignee]
        workload = Counter(i.assignee for i in assigned if i.is_open)
        busiest = workload.most_common(1)
        return (
            MetricCard("Assigned incidents", str(len(assigned))),
            MetricCard(
                "Unassigned",
                str(sum(1 for i in incidents if i.is_open and not i.assignee)),
                tone="warning",
            ),
            MetricCard(
                "Investigation queue",
                str(sum(1 for i in incidents if i.is_open)),
            ),
            MetricCard(
                "Resolved cases",
                str(sum(1 for i in incidents if not i.is_open)),
                tone="success",
            ),
            MetricCard("Comments", str(sum(len(i.comments) for i in incidents))),
            MetricCard(
                "Busiest analyst",
                busiest[0][0] if busiest else "n/a",
                f"{busiest[0][1]} open" if busiest else "",
            ),
        )

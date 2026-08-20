"""SOC command centre routes.

Serves the aggregated operational picture. The whole dashboard is one request so
widgets never issue independent queries, which keeps rendering cheap and makes a
future auto-refresh a single poll.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from services.soc import MetricCard, SocOverview, SocOverviewService


class MetricModel(BaseModel):
    """A labelled metric."""

    label: str
    value: str
    detail: str = ""
    tone: str = "neutral"


class TimelineEventModel(BaseModel):
    """One SOC timeline entry."""

    timestamp: str
    kind: str
    severity: str
    title: str
    detail: str
    artifact_type: str = ""
    incident_id: str = ""
    campaign_id: str = ""


class IncidentSummaryModel(BaseModel):
    """A compact incident row."""

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


class CampaignSummaryModel(BaseModel):
    """A compact campaign card."""

    id: str
    name: str
    category: str
    risk_percent: int
    occurrences: int
    affected_users: int
    first_seen: str
    last_seen: str


class HealthComponentModel(BaseModel):
    """One platform component's health."""

    name: str
    status: str
    detail: str


class SocOverviewResponse(BaseModel):
    """The complete SOC operational picture."""

    threat_level: str
    risk_score: float
    platform_status: str
    generated_at: str
    posture: list[MetricModel]
    incident_metrics: list[MetricModel]
    incident_queue: list[IncidentSummaryModel]
    priority_distribution: list[list[str | int]]
    campaign_metrics: list[MetricModel]
    campaigns: list[CampaignSummaryModel]
    threat_metrics: list[MetricModel]
    top_malicious_urls: list[list[str | int]]
    top_malicious_senders: list[list[str | int]]
    threat_categories: list[list[str | int]]
    artifact_distribution: list[list[str | int]]
    timeline: list[TimelineEventModel]
    analytics: list[MetricModel]
    risk_distribution: list[list[str | int]]
    detection_trend: list[list[str | int]]
    analyst_activity: list[MetricModel]
    recent_comments: list[list[str]]
    health: list[HealthComponentModel]


def _service(request: Request) -> SocOverviewService:
    service: SocOverviewService = request.app.state.soc_service
    return service


def _metrics(cards: tuple[MetricCard, ...]) -> list[MetricModel]:
    return [MetricModel(label=c.label, value=c.value, detail=c.detail, tone=c.tone) for c in cards]


def _pairs(values: tuple[tuple[str, int], ...]) -> list[list[str | int]]:
    return [[name, count] for name, count in values]


def _to_response(overview: SocOverview) -> SocOverviewResponse:
    return SocOverviewResponse(
        threat_level=overview.threat_level,
        risk_score=overview.risk_score,
        platform_status=overview.platform_status,
        generated_at=overview.generated_at,
        posture=_metrics(overview.posture),
        incident_metrics=_metrics(overview.incident_metrics),
        incident_queue=[
            IncidentSummaryModel(
                id=i.id,
                title=i.title,
                category=i.category,
                risk_percent=i.risk_percent,
                status=i.status,
                priority=i.priority,
                assignee=i.assignee,
                occurrences=i.occurrences,
                affected_users=i.affected_users,
                last_seen=i.last_seen,
            )
            for i in overview.incident_queue
        ],
        priority_distribution=_pairs(overview.priority_distribution),
        campaign_metrics=_metrics(overview.campaign_metrics),
        campaigns=[
            CampaignSummaryModel(
                id=c.id,
                name=c.name,
                category=c.category,
                risk_percent=c.risk_percent,
                occurrences=c.occurrences,
                affected_users=c.affected_users,
                first_seen=c.first_seen,
                last_seen=c.last_seen,
            )
            for c in overview.campaigns
        ],
        threat_metrics=_metrics(overview.threat_metrics),
        top_malicious_urls=_pairs(overview.top_malicious_urls),
        top_malicious_senders=_pairs(overview.top_malicious_senders),
        threat_categories=_pairs(overview.threat_categories),
        artifact_distribution=_pairs(overview.artifact_distribution),
        timeline=[
            TimelineEventModel(
                timestamp=e.timestamp,
                kind=e.kind,
                severity=e.severity,
                title=e.title,
                detail=e.detail,
                artifact_type=e.artifact_type,
                incident_id=e.incident_id,
                campaign_id=e.campaign_id,
            )
            for e in overview.timeline
        ],
        analytics=_metrics(overview.analytics),
        risk_distribution=_pairs(overview.risk_distribution),
        detection_trend=_pairs(overview.detection_trend),
        analyst_activity=_metrics(overview.analyst_activity),
        recent_comments=[[author, body] for author, body in overview.recent_comments],
        health=[
            HealthComponentModel(name=h.name, status=h.status, detail=h.detail)
            for h in overview.health
        ],
    )


def build_router() -> APIRouter:
    """Build the SOC command centre router."""
    router = APIRouter(prefix="/api/soc", tags=["soc"])

    @router.get("/overview", response_model=SocOverviewResponse)
    def overview(request: Request) -> SocOverviewResponse:
        """Return the complete operational picture in one request."""
        return _to_response(_service(request).overview())

    return router

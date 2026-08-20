"""Incident and campaign routes.

Exposes correlated incidents, discovered campaigns, artifact relationship
intelligence, and the analyst workflow (assignment, priority, tags, comments,
status). Detection evidence is read-only over this surface; only workflow fields
can be modified.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.constants import IncidentStatus, InvestigationPriority
from core.domain.correlation import ArtifactKind, ArtifactRef
from core.entities import Campaign, Incident
from services.incident import IncidentCorrelationService

_NOT_FOUND = 404
_UNPROCESSABLE = 422


class ArtifactModel(BaseModel):
    """A correlatable observable."""

    kind: str
    value: str
    label: str


class CommentModel(BaseModel):
    """An analyst comment."""

    author: str
    body: str
    created_at: str


class EventModel(BaseModel):
    """An investigation history entry."""

    label: str
    detail: str
    occurred_at: str


class IncidentModel(BaseModel):
    """A correlated incident."""

    id: str
    title: str
    category: str
    risk_score: float
    risk_percent: int
    status: str
    priority: str
    assignee: str
    tags: list[str]
    campaign_id: str
    scan_ids: list[str]
    occurrences: int
    affected_users: list[str]
    artifacts: list[ArtifactModel]
    comments: list[CommentModel]
    events: list[EventModel]
    first_seen: str
    last_seen: str


class CampaignModel(BaseModel):
    """A discovered campaign."""

    id: str
    name: str
    category: str
    risk_percent: int
    occurrences: int
    affected_users: list[str]
    artifacts: list[ArtifactModel]
    first_seen: str
    last_seen: str


class RelationshipResponse(BaseModel):
    """Relationship statements for one observable."""

    artifact: str
    statements: list[str]


class WorkflowRequest(BaseModel):
    """An analyst workflow change."""

    status: IncidentStatus | None = None
    assignee: str | None = None
    priority: InvestigationPriority | None = None
    tags: list[str] | None = None
    comment: str | None = None
    author: str = Field(default="analyst")


def _service(request: Request) -> IncidentCorrelationService:
    service: IncidentCorrelationService = request.app.state.incident_service
    return service


def _artifacts(refs: tuple[ArtifactRef, ...]) -> list[ArtifactModel]:
    return [ArtifactModel(kind=r.kind.value, value=r.value, label=r.label) for r in refs]


def _incident_model(incident: Incident) -> IncidentModel:
    return IncidentModel(
        id=str(incident.id),
        title=incident.title,
        category=incident.category.value,
        risk_score=incident.risk_score,
        risk_percent=incident.risk_percent,
        status=incident.status.value,
        priority=incident.priority.value,
        assignee=incident.assignee,
        tags=list(incident.tags),
        campaign_id=incident.campaign_id,
        scan_ids=list(incident.scan_ids),
        occurrences=incident.occurrences,
        affected_users=list(incident.affected_users),
        artifacts=_artifacts(incident.artifacts),
        comments=[
            CommentModel(author=c.author, body=c.body, created_at=c.created_at.isoformat())
            for c in incident.comments
        ],
        events=[
            EventModel(label=e.label, detail=e.detail, occurred_at=e.occurred_at.isoformat())
            for e in incident.events
        ],
        first_seen=incident.first_seen.isoformat(),
        last_seen=incident.last_seen.isoformat(),
    )


def _campaign_model(campaign: Campaign) -> CampaignModel:
    return CampaignModel(
        id=str(campaign.id),
        name=campaign.name,
        category=campaign.category.value,
        risk_percent=campaign.risk_percent,
        occurrences=campaign.occurrences,
        affected_users=list(campaign.affected_users),
        artifacts=_artifacts(campaign.artifacts),
        first_seen=campaign.first_seen.isoformat(),
        last_seen=campaign.last_seen.isoformat(),
    )


def build_router() -> APIRouter:
    """Build the incident and campaign router."""
    router = APIRouter(prefix="/api", tags=["incidents"])

    @router.get("/incidents", response_model=list[IncidentModel])
    def list_incidents(request: Request) -> list[IncidentModel]:
        """List correlated incidents, most recently seen first."""
        return [_incident_model(i) for i in _service(request).list_incidents()]

    @router.get("/incidents/{incident_id}", response_model=IncidentModel)
    def get_incident(incident_id: str, request: Request) -> IncidentModel:
        """Fetch a single incident."""
        incident = _service(request).get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=_NOT_FOUND, detail="Incident not found")
        return _incident_model(incident)

    @router.put("/incidents/{incident_id}/workflow", response_model=IncidentModel)
    def update_workflow(
        incident_id: str, payload: WorkflowRequest, request: Request
    ) -> IncidentModel:
        """Apply an analyst workflow change to an incident."""
        incident = _service(request).update_workflow(
            incident_id,
            status=payload.status.value if payload.status else None,
            assignee=payload.assignee,
            priority=payload.priority.value if payload.priority else None,
            tags=tuple(payload.tags) if payload.tags is not None else None,
            comment=payload.comment,
            author=payload.author,
        )
        if incident is None:
            raise HTTPException(status_code=_NOT_FOUND, detail="Incident not found")
        return _incident_model(incident)

    @router.get("/campaigns", response_model=list[CampaignModel])
    def list_campaigns(request: Request) -> list[CampaignModel]:
        """List discovered campaigns, most recently seen first."""
        return [_campaign_model(c) for c in _service(request).list_campaigns()]

    @router.get("/relationships", response_model=RelationshipResponse)
    def relationships(kind: str, value: str, request: Request) -> RelationshipResponse:
        """Describe how one observable relates to incidents and campaigns."""
        try:
            artifact = ArtifactRef(kind=ArtifactKind(kind), value=value)
        except ValueError as exc:
            raise HTTPException(status_code=_UNPROCESSABLE, detail=str(exc)) from exc
        return RelationshipResponse(
            artifact=artifact.label,
            statements=list(_service(request).relationships(artifact)),
        )

    return router

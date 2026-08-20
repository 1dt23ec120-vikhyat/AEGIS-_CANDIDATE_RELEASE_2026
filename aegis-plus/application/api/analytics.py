"""Advanced analytics API (M11 Phase E).

Read-only endpoints that expose the SOC analytics overview and the Graph Explorer
overlay, composed from the deterministic M11 analytics engine. These extend the
existing API surface; they add no state and no persistence.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

from core.domain.soc_analytics_view import AnalyticsOverview, GraphOverlay
from services.analytics import AnalyticsOverviewService, GraphOverlayService


class ThreatScoreModel(BaseModel):
    """A threat score for the dashboard."""

    artifact_id: str
    label: str
    severity: float
    confidence: float
    exposure: float
    blast_radius: int
    priority: float
    analyst_urgency: float
    rationale: list[str]


class CampaignIntelModel(BaseModel):
    """Campaign intelligence for the dashboard."""

    campaign_id: str
    label: str
    artifact_count: int
    ioc_count: int
    infrastructure_count: int
    shared_ioc_score: float
    rationale: list[str]


class IOCIntelModel(BaseModel):
    """IOC intelligence for the dashboard."""

    ioc_id: str
    label: str
    frequency: int
    prevalence: float
    confidence: float
    aging_days: float
    rationale: list[str]


class ClusterModel(BaseModel):
    """An infrastructure-reuse cluster."""

    infra_id: str
    infra_type: str
    infra_label: str
    member_ids: list[str]
    rationale: list[str]


class PathModel(BaseModel):
    """A critical attack/compromise path."""

    source_id: str
    target_id: str
    node_ids: list[str]
    hops: int
    rationale: list[str]


class RecommendationModel(BaseModel):
    """An analyst recommendation."""

    kind: str
    title: str
    subject_id: str
    subject_type: str
    priority: float
    rationale: list[str]


class OverviewModel(BaseModel):
    """The aggregate SOC analytics overview."""

    threat_priorities: list[ThreatScoreModel]
    emerging_campaigns: list[CampaignIntelModel]
    ioc_trends: list[IOCIntelModel]
    infrastructure_reuse: list[ClusterModel]
    critical_attack_paths: list[PathModel]
    threat_distribution: list[list[object]]
    recommendations: list[RecommendationModel]


class NodeOverlayModel(BaseModel):
    """Per-node overlay annotations."""

    node_id: str
    risk_percent: int
    is_critical: bool
    campaign_id: str
    cluster_id: str
    on_attack_path: bool
    propagation_rank: int


class RankedNodeModel(BaseModel):
    """A ranked (central) node."""

    node_id: str
    node_type: str
    label: str
    score: float
    degree: int
    risk_percent: int


class OverlayModel(BaseModel):
    """The Graph Explorer overlay."""

    nodes: list[NodeOverlayModel]
    attack_path_ids: list[str]
    critical_ids: list[str]
    top_central: list[RankedNodeModel]


def _overview_model(view: AnalyticsOverview) -> OverviewModel:
    return OverviewModel(
        threat_priorities=[
            ThreatScoreModel(
                artifact_id=s.artifact_id,
                label=s.label,
                severity=s.severity,
                confidence=s.confidence,
                exposure=s.exposure,
                blast_radius=s.blast_radius,
                priority=s.priority,
                analyst_urgency=s.analyst_urgency,
                rationale=list(s.rationale),
            )
            for s in view.threat_priorities
        ],
        emerging_campaigns=[
            CampaignIntelModel(
                campaign_id=c.campaign_id,
                label=c.label,
                artifact_count=c.artifact_count,
                ioc_count=c.ioc_count,
                infrastructure_count=c.infrastructure_count,
                shared_ioc_score=c.shared_ioc_score,
                rationale=list(c.rationale),
            )
            for c in view.emerging_campaigns
        ],
        ioc_trends=[
            IOCIntelModel(
                ioc_id=i.ioc_id,
                label=i.label,
                frequency=i.frequency,
                prevalence=i.prevalence,
                confidence=i.confidence,
                aging_days=i.aging_days,
                rationale=list(i.rationale),
            )
            for i in view.ioc_trends
        ],
        infrastructure_reuse=[
            ClusterModel(
                infra_id=c.infra_id,
                infra_type=c.infra_type,
                infra_label=c.infra_label,
                member_ids=list(c.member_ids),
                rationale=list(c.rationale),
            )
            for c in view.infrastructure_reuse
        ],
        critical_attack_paths=[
            PathModel(
                source_id=p.source_id,
                target_id=p.target_id,
                node_ids=list(p.node_ids),
                hops=p.hops,
                rationale=list(p.rationale),
            )
            for p in view.critical_attack_paths
        ],
        threat_distribution=[[label, count] for label, count in view.threat_distribution],
        recommendations=[
            RecommendationModel(
                kind=r.kind,
                title=r.title,
                subject_id=r.subject_id,
                subject_type=r.subject_type,
                priority=r.priority,
                rationale=list(r.rationale),
            )
            for r in view.recommendations
        ],
    )


def _overlay_model(view: GraphOverlay) -> OverlayModel:
    return OverlayModel(
        nodes=[
            NodeOverlayModel(
                node_id=n.node_id,
                risk_percent=n.risk_percent,
                is_critical=n.is_critical,
                campaign_id=n.campaign_id,
                cluster_id=n.cluster_id,
                on_attack_path=n.on_attack_path,
                propagation_rank=n.propagation_rank,
            )
            for n in view.nodes
        ],
        attack_path_ids=list(view.attack_path_ids),
        critical_ids=list(view.critical_ids),
        top_central=[
            RankedNodeModel(
                node_id=r.node_id,
                node_type=r.node_type,
                label=r.label,
                score=r.score,
                degree=r.degree,
                risk_percent=r.risk_percent,
            )
            for r in view.top_central
        ],
    )


def _overview_service(request: Request) -> AnalyticsOverviewService:
    service: AnalyticsOverviewService = request.app.state.analytics_overview_service
    return service


def _overlay_service(request: Request) -> GraphOverlayService:
    service: GraphOverlayService = request.app.state.graph_overlay_service
    return service


def build_router() -> APIRouter:
    """Build the advanced analytics API router."""
    router = APIRouter(prefix="/api/analytics", tags=["analytics"])

    @router.get("/overview", response_model=OverviewModel)
    def overview(request: Request, top: int = Query(default=5, ge=1, le=50)) -> OverviewModel:
        return _overview_model(_overview_service(request).overview(top=top))

    @router.get("/overlay", response_model=OverlayModel)
    def overlay(request: Request, top: int = Query(default=10, ge=1, le=100)) -> OverlayModel:
        return _overlay_model(_overlay_service(request).overlay(top=top))

    return router

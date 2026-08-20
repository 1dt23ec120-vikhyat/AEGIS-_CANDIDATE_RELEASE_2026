"""Threat intelligence routes.

Exposes the blacklist and auto-protection over HTTP: check a URL, guard an
open attempt, list blacklisted artifacts, fetch one, and read dashboard stats.
The UI reaches all protection features through these endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.domain.url import Url
from core.entities import ThreatEntry
from core.exceptions import ValidationError
from services.threat_intelligence import ThreatIntelligenceService


class UrlRequest(BaseModel):
    """Request body carrying a single URL."""

    url: str = Field(min_length=1, max_length=2048)


class IndicatorModel(BaseModel):
    """A detection indicator."""

    feature: str
    detail: str


class ThreatModel(BaseModel):
    """A blacklist entry."""

    hash: str
    url: str
    artifact_type: str
    verdict: str
    risk_percent: int
    confidence: float
    first_detected: str
    last_detected: str
    detection_count: int
    blocked: bool
    block_source: str
    indicators: list[IndicatorModel]


class ThreatCheckResponse(BaseModel):
    """The result of a blacklist check."""

    blocked: bool
    threat: ThreatModel | None


class ThreatStatsResponse(BaseModel):
    """Aggregate blacklist statistics."""

    total_blacklisted: int
    threats_blocked: int
    high_risk_count: int
    most_recent: str | None


def _service(request: Request) -> ThreatIntelligenceService:
    service: ThreatIntelligenceService = request.app.state.threat_service
    return service


def _to_model(entry: ThreatEntry) -> ThreatModel:
    return ThreatModel(
        hash=entry.artifact_hash,
        url=entry.artifact,
        artifact_type=entry.artifact_type.value,
        verdict=entry.verdict.value,
        risk_percent=round(entry.risk_score * 100),
        confidence=entry.confidence,
        first_detected=entry.first_detected.isoformat(),
        last_detected=entry.last_detected.isoformat(),
        detection_count=entry.detection_count,
        blocked=entry.blocked,
        block_source=entry.block_source.value,
        indicators=[IndicatorModel(feature=i.feature, detail=i.detail) for i in entry.indicators],
    )


def _parse_url(payload: UrlRequest) -> Url:
    try:
        return Url.create(payload.url)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def build_router() -> APIRouter:
    """Build the threat intelligence router."""
    router = APIRouter(prefix="/api/threats", tags=["threat-intelligence"])

    @router.post("/check", response_model=ThreatCheckResponse)
    def check(payload: UrlRequest, request: Request) -> ThreatCheckResponse:
        """Return whether a URL is blacklisted (no side effects)."""
        entry = _service(request).lookup(_parse_url(payload))
        blocked = entry is not None and entry.blocked
        return ThreatCheckResponse(
            blocked=blocked, threat=_to_model(entry) if entry is not None else None
        )

    @router.post("/guard-open", response_model=ThreatCheckResponse)
    def guard_open(payload: UrlRequest, request: Request) -> ThreatCheckResponse:
        """Guard an open attempt; audits a prevented launch when blocked."""
        entry = _service(request).guard_open(_parse_url(payload))
        return ThreatCheckResponse(
            blocked=entry is not None, threat=_to_model(entry) if entry else None
        )

    @router.get("", response_model=list[ThreatModel])
    def list_threats(request: Request) -> list[ThreatModel]:
        """List all blacklisted artifacts, most recent first."""
        return [_to_model(e) for e in _service(request).list_threats()]

    @router.get("/stats", response_model=ThreatStatsResponse)
    def stats(request: Request) -> ThreatStatsResponse:
        """Return aggregate blacklist statistics."""
        s = _service(request).stats()
        return ThreatStatsResponse(
            total_blacklisted=s.total_blacklisted,
            threats_blocked=s.threats_blocked,
            high_risk_count=s.high_risk_count,
            most_recent=s.most_recent,
        )

    @router.get("/{artifact_hash}", response_model=ThreatModel)
    def get_threat(artifact_hash: str, request: Request) -> ThreatModel:
        """Fetch one blacklist entry by hash (audits the view)."""
        entry = _service(request).get_by_hash(artifact_hash)
        if entry is None:
            raise HTTPException(status_code=404, detail="Threat not found")
        return _to_model(entry)

    return router

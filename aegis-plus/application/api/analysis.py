"""URL analysis routes.

Exposes the URL Analysis vertical over HTTP: submit a URL for analysis and list
recent results. Requests are validated by Pydantic; the service (reached from
application state) performs validation, analysis, persistence, and auditing.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.domain import Verdict
from core.entities import UrlScan
from core.exceptions import ValidationError
from services.url_analysis import UrlAnalysisService
from services.url_analysis.service import ScanOutcome


class ScanRequest(BaseModel):
    """Request body for a URL scan."""

    url: str = Field(min_length=1, max_length=2048)


class ContributionModel(BaseModel):
    """An explainable contribution to the threat score."""

    feature: str
    detail: str
    weight: float


class SourceModel(BaseModel):
    """One intelligence source's contribution summary."""

    source: str
    risk_percent: int
    confidence: float
    available: bool
    rationale: str


class ScanResponse(BaseModel):
    """The result of a URL scan."""

    id: str
    url: str
    verdict: str
    threat_score: float
    confidence: float
    risk_percent: int
    category: str
    evidence_strength: float
    blacklisted: bool
    blacklist_hit: bool
    contributions: list[ContributionModel]
    sources: list[SourceModel]


def _service(request: Request) -> UrlAnalysisService:
    service: UrlAnalysisService = request.app.state.url_analysis_service
    return service


def _to_response(outcome: ScanOutcome) -> ScanResponse:
    scan: UrlScan = outcome.scan
    triggered = sorted(
        (c for c in scan.contributions if c.triggered),
        key=lambda c: c.weight,
        reverse=True,
    )
    return ScanResponse(
        id=str(scan.id),
        url=scan.url,
        verdict=scan.verdict.value,
        threat_score=scan.threat_score,
        confidence=scan.confidence,
        risk_percent=round(scan.threat_score * 100),
        category=scan.category.value,
        evidence_strength=scan.evidence_strength,
        blacklisted=outcome.blacklisted,
        blacklist_hit=outcome.blacklist_hit,
        contributions=[
            ContributionModel(feature=c.feature, detail=c.detail, weight=c.weight)
            for c in triggered
        ],
        sources=[
            SourceModel(
                source=s.source.value,
                risk_percent=round(s.risk * 100),
                confidence=s.confidence,
                available=s.available,
                rationale=s.rationale,
            )
            for s in scan.sources
        ],
    )


def build_router() -> APIRouter:
    """Build the URL analysis router."""
    router = APIRouter(prefix="/api/url", tags=["url-analysis"])

    @router.post("/scan", response_model=ScanResponse)
    def scan(payload: ScanRequest, request: Request) -> ScanResponse:
        """Analyze a URL and return the explainable result."""
        try:
            result = _service(request).analyze(payload.url)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _to_response(result)

    @router.get("/scans/recent", response_model=list[ScanResponse])
    def recent(request: Request, limit: int = 10) -> list[ScanResponse]:
        """Return the most recent scans, newest first."""
        return [
            _to_response(
                ScanOutcome(
                    scan=s,
                    blacklisted=s.verdict is Verdict.PHISHING,
                    blacklist_hit=False,
                )
            )
            for s in _service(request).recent(limit)
        ]

    return router

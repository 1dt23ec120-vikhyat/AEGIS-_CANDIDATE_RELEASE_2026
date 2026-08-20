"""Email analysis and investigation routes.

Exposes the Email Analysis vertical over HTTP. Beyond the verdict and evidence,
the scan response carries the full investigation payload an analyst needs -
parsed metadata, per-mechanism authentication results, sender intelligence,
attachment detail, embedded-URL results, and body views - all derived by reusing
the existing analysis. Analyst workflow metadata (status/priority/tags/notes) is
read and written through dedicated investigation routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.constants import InvestigationPriority, InvestigationStatus
from core.domain.email import EmailMessage
from core.entities import EmailInvestigation, EmailScan
from core.exceptions import ValidationError
from services.email_analysis import (
    EmailAnalysisService,
    EmailInvestigationService,
    EmailScanOutcome,
)

_BODY_CAP = 40_000


class EmailScanRequest(BaseModel):
    """Request body for an email scan."""

    content: str = Field(min_length=1, max_length=1_000_000)


class ContributionModel(BaseModel):
    """An explainable contribution."""

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


class EmbeddedUrlModel(BaseModel):
    """An embedded-URL analysis result."""

    url: str
    verdict: str
    risk_percent: int
    blacklisted: bool


class AuthMechanismModel(BaseModel):
    """A single SPF/DKIM/DMARC result."""

    name: str
    status: str
    reason: str
    impact: str


class OverviewModel(BaseModel):
    """Parsed email metadata."""

    from_display: str
    from_address: str
    to: list[str]
    cc: list[str]
    bcc: list[str]
    subject: str
    date: str
    reply_to: str
    return_path: str
    message_id: str
    mime_version: str
    content_type: str
    priority: str


class SenderIntelModel(BaseModel):
    """Sender investigation summary."""

    display_name: str
    address: str
    domain: str
    reply_to: str
    reply_to_mismatch: bool
    brand_impersonation: bool
    impersonation_detail: str
    prior_scans: int
    prior_malicious: int


class AttachmentModel(BaseModel):
    """Attachment metadata and risk."""

    filename: str
    extension: str
    size: int
    content_type: str
    sha256: str
    indicators: list[str]
    yara_scan: str = "not_available"
    malware_scan: str = "not_available"
    sandbox: str = "not_available"


class BodyModel(BaseModel):
    """Email body views."""

    plain: str
    html: str
    raw: str


class EmailScanResponse(BaseModel):
    """The result of an email scan."""

    id: str
    sender: str
    subject: str
    verdict: str
    category: str
    threat_score: float
    confidence: float
    risk_percent: int
    evidence_strength: float
    malicious: bool
    url_count: int
    malicious_url_count: int
    contributions: list[ContributionModel]
    sources: list[SourceModel]
    urls: list[EmbeddedUrlModel]
    authentication: list[AuthMechanismModel]
    overview: OverviewModel | None
    sender_intel: SenderIntelModel | None
    attachments: list[AttachmentModel]
    body: BodyModel | None
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    correlation_rationale: str = ""


class InvestigationModel(BaseModel):
    """Analyst workflow metadata."""

    scan_id: str
    status: str
    priority: str
    tags: list[str]
    notes: str


class InvestigationRequest(BaseModel):
    """Request body to update an investigation."""

    status: InvestigationStatus
    priority: InvestigationPriority
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


def _service(request: Request) -> EmailAnalysisService:
    service: EmailAnalysisService = request.app.state.email_analysis_service
    return service


def _investigations(request: Request) -> EmailInvestigationService:
    service: EmailInvestigationService = request.app.state.email_investigation_service
    return service


def _overview(email: EmailMessage) -> OverviewModel:
    return OverviewModel(
        from_display=email.sender.display_name,
        from_address=email.sender.address,
        to=[a.address for a in email.recipients],
        cc=[a.address for a in email.cc],
        bcc=[a.address for a in email.bcc],
        subject=email.subject,
        date=email.date,
        reply_to=email.reply_to.address if email.reply_to else "",
        return_path=email.return_path,
        message_id=email.message_id,
        mime_version=email.mime_version,
        content_type=email.content_type,
        priority=email.priority,
    )


def _sender_intel(outcome: EmailScanOutcome, email: EmailMessage) -> SenderIntelModel:
    triggered = {c.feature: c.detail for c in outcome.scan.contributions if c.triggered}
    return SenderIntelModel(
        display_name=email.sender.display_name,
        address=email.sender.address,
        domain=email.sender.domain,
        reply_to=email.reply_to.address if email.reply_to else "",
        reply_to_mismatch="reply_to_mismatch" in triggered,
        brand_impersonation="brand_impersonation" in triggered,
        impersonation_detail=triggered.get("brand_impersonation", ""),
        prior_scans=outcome.prior_sender_scans,
        prior_malicious=outcome.prior_sender_malicious,
    )


def _to_response(outcome: EmailScanOutcome) -> EmailScanResponse:
    scan: EmailScan = outcome.scan
    email = outcome.email
    triggered = sorted(
        (c for c in scan.contributions if c.triggered),
        key=lambda c: c.weight,
        reverse=True,
    )
    authentication = (
        [
            AuthMechanismModel(name=m.name, status=m.status.value, reason=m.reason, impact=m.impact)
            for m in email.authentication_breakdown()
        ]
        if email
        else []
    )
    attachments = (
        [
            AttachmentModel(
                filename=a.filename,
                extension=a.extension,
                size=a.size,
                content_type=a.content_type,
                sha256=a.sha256,
                indicators=list(a.risk_indicators),
            )
            for a in email.attachments
        ]
        if email
        else []
    )
    body = (
        BodyModel(
            plain=email.body[:_BODY_CAP],
            html=email.html_body[:_BODY_CAP],
            raw=email.raw[:_BODY_CAP],
        )
        if email
        else None
    )
    return EmailScanResponse(
        id=str(scan.id),
        sender=scan.sender,
        subject=scan.subject,
        verdict=scan.verdict.value,
        category=scan.category.value,
        threat_score=scan.threat_score,
        confidence=scan.confidence,
        risk_percent=round(scan.threat_score * 100),
        evidence_strength=scan.evidence_strength,
        malicious=outcome.malicious,
        url_count=scan.url_count,
        malicious_url_count=scan.malicious_url_count,
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
        urls=[
            EmbeddedUrlModel(
                url=u.url,
                verdict=u.verdict,
                risk_percent=u.risk_percent,
                blacklisted=u.blacklisted,
            )
            for u in outcome.urls
        ],
        authentication=authentication,
        overview=_overview(email) if email else None,
        sender_intel=_sender_intel(outcome, email) if email else None,
        attachments=attachments,
        body=body,
        incident_id=outcome.incident_id,
        incident_title=outcome.incident_title,
        campaign_name=outcome.campaign_name,
        correlation_rationale=outcome.correlation_rationale,
    )


def _recent_to_response(scan: EmailScan) -> EmailScanResponse:
    return _to_response(
        EmailScanOutcome(scan=scan, malicious=scan.verdict.value == "phishing", urls=())
    )


def _investigation_model(
    scan_id: str, investigation: EmailInvestigation | None
) -> InvestigationModel:
    if investigation is None:
        return InvestigationModel(
            scan_id=scan_id,
            status=InvestigationStatus.OPEN.value,
            priority=InvestigationPriority.MEDIUM.value,
            tags=[],
            notes="",
        )
    return InvestigationModel(
        scan_id=investigation.scan_id,
        status=investigation.status.value,
        priority=investigation.priority.value,
        tags=list(investigation.tags),
        notes=investigation.notes,
    )


def build_router() -> APIRouter:
    """Build the email analysis and investigation router."""
    router = APIRouter(prefix="/api/email", tags=["email-analysis"])

    @router.post("/scan", response_model=EmailScanResponse)
    def scan(payload: EmailScanRequest, request: Request) -> EmailScanResponse:
        """Analyze a raw email and return the full investigation payload."""
        try:
            result = _service(request).analyze(payload.content)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _to_response(result)

    @router.get("/scans/recent", response_model=list[EmailScanResponse])
    def recent(request: Request, limit: int = 10) -> list[EmailScanResponse]:
        """Return the most recent email scans, newest first."""
        return [_recent_to_response(s) for s in _service(request).recent(limit)]

    @router.get("/scans/{scan_id}", response_model=EmailScanResponse)
    def get_scan(scan_id: str, request: Request) -> EmailScanResponse:
        """Return a persisted email scan by id (opens the investigation workspace).

        Reuses the existing scan projection so a Gmail-derived message can open
        the *existing* Email Investigation experience via its ``scan_id`` without
        re-analyzing anything.
        """
        scan = _service(request).get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return _recent_to_response(scan)

    @router.get("/investigations/{scan_id}", response_model=InvestigationModel)
    def get_investigation(scan_id: str, request: Request) -> InvestigationModel:
        """Return the analyst investigation for a scan (defaults if unset)."""
        return _investigation_model(scan_id, _investigations(request).get(scan_id))

    @router.put("/investigations/{scan_id}", response_model=InvestigationModel)
    def save_investigation(
        scan_id: str, payload: InvestigationRequest, request: Request
    ) -> InvestigationModel:
        """Create or update the analyst investigation for a scan."""
        investigation = _investigations(request).save(
            scan_id,
            status=payload.status,
            priority=payload.priority,
            tags=tuple(payload.tags),
            notes=payload.notes,
        )
        return _investigation_model(scan_id, investigation)

    return router

"""Gmail connector routes (M14).

Exposes the read-only Gmail *input connector* over HTTP. Every route is mounted
behind the existing AEGIS+ session guard (``require_session``) in the API
composition root — this is the AEGIS+ application-login boundary and is entirely
separate from the Gmail OAuth identity, which authorizes AEGIS+ to *read* Gmail.

No response ever carries an OAuth token, authorization code, or client secret:
the DTOs expose only connection status, the account address, and synchronization
statistics. The interactive connect flow (which opens the system browser and
waits for the loopback callback) runs on FastAPI's threadpool because the handler
is declared ``def`` (sync), so the event loop is never blocked.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.interfaces.gmail import GmailAuthError, GmailConnectorError
from services.gmail import (
    GmailConnectionStatus,
    GmailIngestionService,
    GmailMessageDetail,
    GmailMessageView,
    GmailPreview,
    GmailSyncResult,
    GmailUrlItem,
)


class GmailStatusModel(BaseModel):
    """Connection status (never carries token material)."""

    connected: bool
    email_address: str = ""
    scope: str = ""
    read_only: bool = True
    processed_messages: int = 0
    last_synced_at: str = ""


class GmailMessageOutcomeModel(BaseModel):
    """One message's ingestion outcome."""

    message_id: str
    subject: str = ""
    sender: str = ""
    verdict: str = ""
    analyzed: bool = False
    status: str = "analyzed"
    duplicate: bool = False
    error: str = ""


class GmailSyncResultModel(BaseModel):
    """Aggregate synchronization statistics."""

    retrieved: int
    analyzed: int
    duplicates: int
    malicious: int
    suspicious: int
    benign: int
    errors: int
    unsupported: int = 0
    transient: int = 0
    failed: int = 0
    synced_at: str = ""
    outcomes: list[GmailMessageOutcomeModel] = Field(default_factory=list)


class GmailSyncRequest(BaseModel):
    """Optional overrides for a synchronization pass."""

    query: str | None = Field(default=None, max_length=512)
    max_messages: int | None = Field(default=None, ge=1, le=100)


class GmailMessageModel(BaseModel):
    """A row in the analyst message list (never carries token material)."""

    message_id: str
    thread_id: str = ""
    sender: str = ""
    subject: str = ""
    received_at: str = ""
    snippet: str = ""
    status: str
    risk_band: str
    verdict: str = ""
    risk_percent: int = 0
    confidence: float = 0.0
    scan_id: str = ""


class GmailUrlModel(BaseModel):
    """An embedded URL surfaced for inspection — always treated as untrusted."""

    url: str
    verdict: str
    risk_percent: int
    blacklisted: bool


class GmailEvidenceModel(BaseModel):
    """One triggered explainable contribution from the existing scan."""

    feature: str
    detail: str
    weight: float


class GmailSourceModel(BaseModel):
    """One intelligence source's contribution summary from the existing scan."""

    source: str
    risk_percent: int
    confidence: float
    available: bool
    rationale: str


class GmailPreviewModel(BaseModel):
    """A safe, non-executable preview of the message (plain text only)."""

    from_display: str = ""
    from_address: str = ""
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    date: str = ""
    reply_to: str = ""
    plain_body: str = ""
    urls: list[GmailUrlModel] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)
    error: str = ""


class GmailMessageDetailModel(BaseModel):
    """The full analyst detail for one Gmail message."""

    message: GmailMessageModel
    category: str = ""
    evidence_strength: float = 0.0
    url_count: int = 0
    malicious_url_count: int = 0
    evidence: list[GmailEvidenceModel] = Field(default_factory=list)
    sources: list[GmailSourceModel] = Field(default_factory=list)
    urls: list[GmailUrlModel] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    artifact_id: str = ""
    preview: GmailPreviewModel | None = None
    analysis_error: str = ""


def _service(request: Request) -> GmailIngestionService:
    return request.app.state.gmail_service  # type: ignore[no-any-return]


def _status_model(status: GmailConnectionStatus) -> GmailStatusModel:
    return GmailStatusModel(
        connected=status.connected,
        email_address=status.email_address,
        scope=status.scope,
        read_only=status.read_only,
        processed_messages=status.processed_messages,
        last_synced_at=status.last_synced_at,
    )


def _sync_model(result: GmailSyncResult) -> GmailSyncResultModel:
    return GmailSyncResultModel(
        retrieved=result.retrieved,
        analyzed=result.analyzed,
        duplicates=result.duplicates,
        malicious=result.malicious,
        suspicious=result.suspicious,
        benign=result.benign,
        errors=result.errors,
        unsupported=result.unsupported,
        transient=result.transient,
        failed=result.failed,
        synced_at=result.synced_at,
        outcomes=[
            GmailMessageOutcomeModel(
                message_id=o.message_id,
                subject=o.subject,
                sender=o.sender,
                verdict=o.verdict,
                analyzed=o.analyzed,
                status=o.status,
                duplicate=o.duplicate,
                error=o.error,
            )
            for o in result.outcomes
        ],
    )


def _message_model(view: GmailMessageView) -> GmailMessageModel:
    return GmailMessageModel(
        message_id=view.message_id,
        thread_id=view.thread_id,
        sender=view.sender,
        subject=view.subject,
        received_at=view.received_at,
        snippet=view.snippet,
        status=view.status.value,
        risk_band=view.risk_band,
        verdict=view.verdict,
        risk_percent=view.risk_percent,
        confidence=view.confidence,
        scan_id=view.scan_id,
    )


def _url_model(url: GmailUrlItem) -> GmailUrlModel:
    return GmailUrlModel(
        url=url.url,
        verdict=url.verdict,
        risk_percent=url.risk_percent,
        blacklisted=url.blacklisted,
    )


def _preview_model(preview: GmailPreview | None) -> GmailPreviewModel | None:
    if preview is None:
        return None
    return GmailPreviewModel(
        from_display=preview.from_display,
        from_address=preview.from_address,
        to=list(preview.to),
        cc=list(preview.cc),
        subject=preview.subject,
        date=preview.date,
        reply_to=preview.reply_to,
        plain_body=preview.plain_body,
        urls=[_url_model(u) for u in preview.urls],
        attachments=list(preview.attachments),
        error=preview.error,
    )


def _detail_model(detail: GmailMessageDetail) -> GmailMessageDetailModel:
    return GmailMessageDetailModel(
        message=_message_model(detail.view),
        category=detail.category,
        evidence_strength=detail.evidence_strength,
        url_count=detail.url_count,
        malicious_url_count=detail.malicious_url_count,
        evidence=[
            GmailEvidenceModel(feature=e.feature, detail=e.detail, weight=e.weight)
            for e in detail.evidence
        ],
        sources=[
            GmailSourceModel(
                source=s.source,
                risk_percent=s.risk_percent,
                confidence=s.confidence,
                available=s.available,
                rationale=s.rationale,
            )
            for s in detail.sources
        ],
        urls=[_url_model(u) for u in detail.urls],
        iocs=list(detail.iocs),
        recommendations=list(detail.recommendations),
        incident_id=detail.incident_id,
        incident_title=detail.incident_title,
        campaign_name=detail.campaign_name,
        artifact_id=detail.artifact_id,
        preview=_preview_model(detail.preview),
        analysis_error=detail.analysis_error,
    )


def build_router() -> APIRouter:
    """Build the Gmail connector router."""
    router = APIRouter(prefix="/api/gmail", tags=["gmail"])

    @router.get("/status", response_model=GmailStatusModel)
    def status(request: Request) -> GmailStatusModel:
        """Return the current Gmail connection status."""
        return _status_model(_service(request).status())

    @router.post("/connect", response_model=GmailStatusModel)
    def connect(request: Request) -> GmailStatusModel:
        """Run the loopback OAuth flow and connect the Gmail account.

        Runs on the threadpool (sync handler): it opens the system browser and
        waits for the loopback callback without blocking the event loop.
        """
        try:
            return _status_model(_service(request).connect())
        except GmailAuthError as exc:
            raise HTTPException(status_code=400, detail=_safe(exc)) from exc
        except GmailConnectorError as exc:
            raise HTTPException(status_code=502, detail=_safe(exc)) from exc

    @router.post("/disconnect", response_model=GmailStatusModel)
    def disconnect(request: Request) -> GmailStatusModel:
        """Disconnect Gmail: clear tokens and sync state (keeps intelligence)."""
        return _status_model(_service(request).disconnect())

    @router.post("/sync", response_model=GmailSyncResultModel)
    def sync(payload: GmailSyncRequest, request: Request) -> GmailSyncResultModel:
        """Fetch recent messages and analyze new ones via the existing pipeline."""
        try:
            result = _service(request).sync(query=payload.query, max_messages=payload.max_messages)
        except GmailAuthError as exc:
            raise HTTPException(status_code=401, detail=_safe(exc)) from exc
        except GmailConnectorError as exc:
            raise HTTPException(status_code=502, detail=_safe(exc)) from exc
        return _sync_model(result)

    @router.get("/messages", response_model=list[GmailMessageModel])
    def messages(
        request: Request, risk_filter: str = "all", search: str = ""
    ) -> list[GmailMessageModel]:
        """Return the analyst message list for the active account.

        Projects the persisted read-model rows into display views, surfacing the
        *existing* verdict/risk for analyzed messages. Filtering and search are
        presentation concerns; no intelligence is computed here.
        """
        views = _service(request).list_messages(risk_filter=risk_filter, search=search)
        return [_message_model(v) for v in views]

    @router.get("/messages/{message_id}", response_model=GmailMessageDetailModel)
    def message_detail(message_id: str, request: Request) -> GmailMessageDetailModel:
        """Return the full analyst detail for one message (existing analysis)."""
        detail = _service(request).message_detail(message_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Message not found.")
        return _detail_model(detail)

    return router


def _safe(error: Exception) -> str:
    """A user-safe error message (never leaks tokens, paths, or internals)."""
    text = str(error)
    return text if text else "Gmail request could not be completed."

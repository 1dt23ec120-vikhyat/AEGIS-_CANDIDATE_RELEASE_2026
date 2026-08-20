"""File analysis and investigation routes.

Exposes the File Intelligence vertical over HTTP. A file is uploaded as multipart
form data, analyzed statically (never executed), and returned with its
fingerprints, type, entropy, extracted indicators, embedded-URL results, and the
explainable evidence behind the verdict. Analyst workflow metadata
(status/priority/tags/notes) is read and written through dedicated investigation
routes, mirroring the email vertical.

Uploaded bytes exist only for the duration of the request and are never persisted.
Size and emptiness are enforced server-side by the ingestion layer.
"""

from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from core.constants import InvestigationPriority, InvestigationStatus
from core.domain.investigation import EvidenceNode, InvestigationSummary
from core.entities import FileInvestigation, FileScan
from core.exceptions import ValidationError
from services.file_analysis import (
    FileAnalysisService,
    FileInvestigationService,
    FileScanOutcome,
)
from services.investigation import build_file_investigation

_MAX_UPLOAD = 25 * 1024 * 1024
_UPLOAD: UploadFile = File(...)


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


class IndicatorsModel(BaseModel):
    """Extracted indicators of compromise."""

    urls: list[str]
    domains: list[str]
    ipv4_addresses: list[str]
    emails: list[str]
    hashes: list[str]
    total: int


class FileOverviewModel(BaseModel):
    """Parsed file metadata."""

    filename: str
    size: int
    sha256: str
    sha1: str
    md5: str
    file_kind: str
    detected_mime: str
    declared_mime: str
    extension: str
    entropy: float
    entropy_descriptor: str
    mime_mismatch: bool
    double_extension: bool
    is_executable: bool
    is_script: bool
    is_archive: bool


class InvestigationEventModel(BaseModel):
    """One timeline event in the unified investigation."""

    timestamp: str
    kind: str
    source: str
    description: str
    detail: str = ""


class EvidenceNodeModel(BaseModel):
    """A node in the recursive evidence tree."""

    label: str
    detail: str = ""
    risk: float = 0.0
    confidence: float = 0.0
    technique_id: str = ""
    recommendation: str = ""
    tone: str = "neutral"
    children: list[EvidenceNodeModel] = Field(default_factory=list)


class MetadataFieldModel(BaseModel):
    """One adaptive metadata key-value pair."""

    label: str
    value: str
    category: str = "general"


class InvestigationSummaryModel(BaseModel):
    """The unified investigation model, serialized for the workspace."""

    investigation_id: str = ""
    artifact_id: str = ""
    artifact_type: str = ""
    status: str = "open"
    created_at: str = ""
    updated_at: str = ""
    analysis_duration_ms: float = 0.0
    verdict: str = ""
    severity: str = "info"
    confidence: float = 0.0
    confidence_source: str = ""
    category: str = "none"
    risk_percent: int = 0
    evidence_strength: float = 0.0
    malicious: bool = False
    timeline: list[InvestigationEventModel] = Field(default_factory=list)
    evidence_tree: list[EvidenceNodeModel] = Field(default_factory=list)
    metadata: list[MetadataFieldModel] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    relationships: list[list[str | float]] = Field(default_factory=list)
    provider_diagnostics: list[list[str | float | int]] = Field(default_factory=list)
    threat_history: list[str] = Field(default_factory=list)
    performance: dict[str, float] = Field(default_factory=dict)


EvidenceNodeModel.model_rebuild()


class FileScanResponse(BaseModel):
    """The result of a file scan."""

    id: str
    filename: str
    verdict: str
    category: str
    threat_score: float
    confidence: float
    risk_percent: int
    evidence_strength: float
    malicious: bool
    size: int
    sha256: str
    file_kind: str
    entropy: float
    indicator_count: int
    url_count: int
    malicious_url_count: int
    contributions: list[ContributionModel]
    sources: list[SourceModel]
    urls: list[EmbeddedUrlModel]
    indicators: IndicatorsModel | None
    overview: FileOverviewModel | None
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    correlation_rationale: str = ""
    investigation: InvestigationSummaryModel | None = None


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


def _service(request: Request) -> FileAnalysisService:
    service: FileAnalysisService = request.app.state.file_analysis_service
    return service


def _investigations(request: Request) -> FileInvestigationService:
    service: FileInvestigationService = request.app.state.file_investigation_service
    return service


def _overview(outcome: FileScanOutcome) -> FileOverviewModel:
    artifact = outcome.artifact
    return FileOverviewModel(
        filename=artifact.filename,
        size=artifact.size,
        sha256=artifact.fingerprints.sha256,
        sha1=artifact.fingerprints.sha1,
        md5=artifact.fingerprints.md5,
        file_kind=artifact.file_type.kind.value,
        detected_mime=artifact.file_type.detected_mime,
        declared_mime=artifact.file_type.declared_mime,
        extension=artifact.file_type.extension,
        entropy=round(artifact.entropy.entropy, 4),
        entropy_descriptor=artifact.entropy.descriptor,
        mime_mismatch=artifact.file_type.mime_mismatch,
        double_extension=artifact.metadata.has_double_extension,
        is_executable=artifact.metadata.is_executable,
        is_script=artifact.metadata.is_script,
        is_archive=artifact.metadata.is_archive,
    )


def _indicators(outcome: FileScanOutcome) -> IndicatorsModel:
    iocs = outcome.indicators
    return IndicatorsModel(
        urls=list(iocs.urls),
        domains=list(iocs.domains),
        ipv4_addresses=list(iocs.ipv4_addresses),
        emails=list(iocs.emails),
        hashes=list(iocs.hashes),
        total=iocs.total,
    )


def _evidence_node_model(node: EvidenceNode) -> EvidenceNodeModel:
    """Serialize a (recursive) evidence-tree node."""
    return EvidenceNodeModel(
        label=node.label,
        detail=node.detail,
        risk=node.risk,
        confidence=node.confidence,
        technique_id=node.technique_id,
        recommendation=node.recommendation,
        tone=node.tone,
        children=[_evidence_node_model(child) for child in node.children],
    )


def _summary_model(summary: InvestigationSummary) -> InvestigationSummaryModel:
    """Serialize a unified :class:`InvestigationSummary` for transport."""
    return InvestigationSummaryModel(
        investigation_id=summary.investigation_id,
        artifact_id=summary.artifact_id,
        artifact_type=summary.artifact_type,
        status=summary.status,
        created_at=summary.created_at,
        updated_at=summary.updated_at,
        analysis_duration_ms=summary.analysis_duration_ms,
        verdict=summary.verdict,
        severity=summary.severity,
        confidence=summary.confidence,
        confidence_source=summary.confidence_source,
        category=summary.category,
        risk_percent=summary.risk_percent,
        evidence_strength=summary.evidence_strength,
        malicious=summary.malicious,
        timeline=[
            InvestigationEventModel(
                timestamp=e.timestamp,
                kind=e.kind.value,
                source=e.source,
                description=e.description,
                detail=e.detail,
            )
            for e in summary.timeline
        ],
        evidence_tree=[_evidence_node_model(n) for n in summary.evidence_tree],
        metadata=[
            MetadataFieldModel(label=m.label, value=m.value, category=m.category)
            for m in summary.metadata
        ],
        recommendations=list(summary.recommendations),
        technique_ids=list(summary.technique_ids),
        relationships=[list(rel) for rel in summary.relationships],
        provider_diagnostics=[list(diag) for diag in summary.provider_diagnostics],
        threat_history=list(summary.threat_history),
        performance=dict(summary.performance),
    )


def _investigation_summary(
    outcome: FileScanOutcome,
    contributions: list[ContributionModel],
    sources: list[SourceModel],
) -> InvestigationSummary:
    """Build the unified investigation summary server-side.

    Construction lives behind the API boundary so the UI receives a ready DTO
    and never imports service code (Clean Architecture dependency rule).
    """
    scan = outcome.scan
    artifact = outcome.artifact
    provider_diagnostics = tuple(
        (s.source.replace("_", " ").title(), "1.0.0", 0.0, 1) for s in sources if s.available
    )
    return build_file_investigation(
        scan_id=str(scan.id),
        filename=scan.filename,
        verdict=scan.verdict.value,
        category=scan.category.value,
        risk_percent=round(scan.threat_score * 100),
        confidence=scan.confidence,
        evidence_strength=scan.evidence_strength,
        malicious=outcome.malicious,
        size=scan.size,
        sha256=scan.sha256,
        sha1=artifact.fingerprints.sha1,
        md5=artifact.fingerprints.md5,
        file_kind=scan.file_kind,
        detected_mime=artifact.file_type.detected_mime,
        declared_mime=artifact.file_type.declared_mime,
        extension=artifact.file_type.extension,
        entropy=round(artifact.entropy.entropy, 4),
        entropy_descriptor=artifact.entropy.descriptor,
        is_executable=artifact.metadata.is_executable,
        is_script=artifact.metadata.is_script,
        is_archive=artifact.metadata.is_archive,
        mime_mismatch=artifact.file_type.mime_mismatch,
        double_extension=artifact.metadata.has_double_extension,
        indicator_count=scan.indicator_count,
        url_count=scan.url_count,
        malicious_url_count=scan.malicious_url_count,
        contributions=contributions,
        sources=sources,
        urls=(),
        indicators=None,
        incident_id=outcome.incident_id,
        incident_title=outcome.incident_title,
        campaign_name=outcome.campaign_name,
        correlation_rationale=outcome.correlation_rationale,
        provider_diagnostics=provider_diagnostics,
    )


def _to_response(outcome: FileScanOutcome) -> FileScanResponse:
    scan: FileScan = outcome.scan
    triggered = sorted(
        (c for c in scan.contributions if c.triggered),
        key=lambda c: c.weight,
        reverse=True,
    )
    contributions = [
        ContributionModel(feature=c.feature, detail=c.detail, weight=c.weight) for c in triggered
    ]
    sources = [
        SourceModel(
            source=s.source.value,
            risk_percent=round(s.risk * 100),
            confidence=s.confidence,
            available=s.available,
            rationale=s.rationale,
        )
        for s in scan.sources
    ]
    return FileScanResponse(
        id=str(scan.id),
        filename=scan.filename,
        verdict=scan.verdict.value,
        category=scan.category.value,
        threat_score=scan.threat_score,
        confidence=scan.confidence,
        risk_percent=round(scan.threat_score * 100),
        evidence_strength=scan.evidence_strength,
        malicious=outcome.malicious,
        size=scan.size,
        sha256=scan.sha256,
        file_kind=scan.file_kind,
        entropy=round(scan.entropy, 4),
        indicator_count=scan.indicator_count,
        url_count=scan.url_count,
        malicious_url_count=scan.malicious_url_count,
        contributions=contributions,
        sources=sources,
        urls=[
            EmbeddedUrlModel(
                url=u.url,
                verdict=u.verdict,
                risk_percent=u.risk_percent,
                blacklisted=u.blacklisted,
            )
            for u in outcome.urls
        ],
        indicators=_indicators(outcome),
        overview=_overview(outcome),
        incident_id=outcome.incident_id,
        incident_title=outcome.incident_title,
        campaign_name=outcome.campaign_name,
        correlation_rationale=outcome.correlation_rationale,
        investigation=_summary_model(_investigation_summary(outcome, contributions, sources)),
    )


def _recent_to_response(scan: FileScan) -> FileScanResponse:
    """Render a stored scan without its (never-persisted) transient artifact."""
    triggered = sorted(
        (c for c in scan.contributions if c.triggered),
        key=lambda c: c.weight,
        reverse=True,
    )
    return FileScanResponse(
        id=str(scan.id),
        filename=scan.filename,
        verdict=scan.verdict.value,
        category=scan.category.value,
        threat_score=scan.threat_score,
        confidence=scan.confidence,
        risk_percent=round(scan.threat_score * 100),
        evidence_strength=scan.evidence_strength,
        malicious=scan.verdict.value == "phishing",
        size=scan.size,
        sha256=scan.sha256,
        file_kind=scan.file_kind,
        entropy=round(scan.entropy, 4),
        indicator_count=scan.indicator_count,
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
        urls=[],
        indicators=None,
        overview=None,
    )


def _investigation_model(
    scan_id: str, investigation: FileInvestigation | None
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
    """Build the file analysis and investigation router."""
    router = APIRouter(prefix="/api/files", tags=["file-analysis"])

    @router.post("/scan", response_model=FileScanResponse)
    async def scan(
        request: Request,
        upload: UploadFile = _UPLOAD,
    ) -> FileScanResponse:
        """Analyze an uploaded file and return its full intelligence payload."""
        data = await upload.read()
        if len(data) > _MAX_UPLOAD:
            raise HTTPException(status_code=413, detail="File exceeds the upload limit")
        filename = upload.filename or "unnamed"
        try:
            result = _service(request).analyze(filename, data)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _to_response(result)

    @router.get("/scans/recent", response_model=list[FileScanResponse])
    def recent(request: Request, limit: int = 10) -> list[FileScanResponse]:
        """Return the most recent file scans, newest first."""
        return [_recent_to_response(s) for s in _service(request).recent(limit)]

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

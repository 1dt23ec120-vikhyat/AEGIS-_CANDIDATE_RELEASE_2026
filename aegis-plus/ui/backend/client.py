"""Backend HTTP client.

The UI's gateway to the embedded FastAPI backend. It is the only way the
presentation layer reaches application services, preserving the architectural
boundary that the UI never imports services or infrastructure directly (ADR-002).

Calls are synchronous; long-running or polling calls must be run off the UI
thread (see :mod:`ui.backend.health_poller`).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

import httpx

from core.domain.analytics_view import RankedNode
from core.domain.attack_view import CompromisePath, InfrastructureCluster
from core.domain.copilot import (
    Citation,
    ContextItem,
    CopilotResponse,
    CopilotStreamEvent,
    GroundingViolation,
    PromptMetadata,
)
from core.domain.graph_view import (
    ConnectedEntity,
    GraphAnalyticsSummary,
    GraphEdgeView,
    GraphNodeView,
    GraphPathView,
    GraphSearchResult,
    GraphSelection,
    GraphSnapshotView,
    GraphView,
)
from core.domain.intelligence_view import (
    CampaignIntelligence,
    IOCIntelligence,
    ThreatScore,
)
from core.domain.investigation import (
    EventKind,
    EvidenceNode,
    InvestigationEvent,
    InvestigationSummary,
    MetadataField,
)
from core.domain.recommendation_view import Recommendation
from core.domain.soc_analytics_view import AnalyticsOverview, GraphOverlay, NodeOverlay

_HTTP_UNPROCESSABLE = 422
_HTTP_TOO_LARGE = 413


@dataclass(frozen=True, slots=True)
class GmailStatusDTO:
    """Gmail connection status for the UI (never carries token material)."""

    connected: bool
    email_address: str = ""
    scope: str = ""
    read_only: bool = True
    processed_messages: int = 0
    last_synced_at: str = ""
    error: str = ""


@dataclass(frozen=True, slots=True)
class GmailSyncDTO:
    """Result of a Gmail synchronization for the UI."""

    retrieved: int = 0
    analyzed: int = 0
    duplicates: int = 0
    malicious: int = 0
    suspicious: int = 0
    benign: int = 0
    errors: int = 0
    unsupported: int = 0
    transient: int = 0
    failed: int = 0
    synced_at: str = ""
    ok: bool = True
    error: str = ""


@dataclass(frozen=True, slots=True)
class GmailMessageDTO:
    """A row in the analyst Gmail message list."""

    message_id: str
    thread_id: str = ""
    sender: str = ""
    subject: str = ""
    received_at: str = ""
    snippet: str = ""
    status: str = "analyzed"
    risk_band: str = "unanalyzed"
    verdict: str = ""
    risk_percent: int = 0
    confidence: float = 0.0
    scan_id: str = ""


@dataclass(frozen=True, slots=True)
class GmailUrlDTO:
    """An embedded URL surfaced for inspection — always untrusted."""

    url: str
    verdict: str = "untrusted"
    risk_percent: int = 0
    blacklisted: bool = False


@dataclass(frozen=True, slots=True)
class GmailEvidenceDTO:
    """A triggered explainable contribution from the existing scan."""

    feature: str
    detail: str
    weight: float


@dataclass(frozen=True, slots=True)
class GmailSourceDTO:
    """An intelligence source's contribution summary from the existing scan."""

    source: str
    risk_percent: int
    confidence: float
    available: bool
    rationale: str


@dataclass(frozen=True, slots=True)
class GmailPreviewDTO:
    """A safe, non-executable preview of the message (plain text only)."""

    from_display: str = ""
    from_address: str = ""
    to: tuple[str, ...] = ()
    cc: tuple[str, ...] = ()
    subject: str = ""
    date: str = ""
    reply_to: str = ""
    plain_body: str = ""
    urls: tuple[GmailUrlDTO, ...] = ()
    attachments: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True, slots=True)
class GmailMessageDetailDTO:
    """The full analyst detail for one Gmail message."""

    message: GmailMessageDTO
    category: str = ""
    evidence_strength: float = 0.0
    url_count: int = 0
    malicious_url_count: int = 0
    evidence: tuple[GmailEvidenceDTO, ...] = ()
    sources: tuple[GmailSourceDTO, ...] = ()
    urls: tuple[GmailUrlDTO, ...] = ()
    iocs: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    artifact_id: str = ""
    preview: GmailPreviewDTO | None = None
    analysis_error: str = ""
    ok: bool = True
    error: str = ""


@dataclass(frozen=True, slots=True)
class HealthResult:
    """Outcome of a backend health query."""

    ok: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class AuthUser:
    """The authenticated account as seen by the UI (never carries a hash)."""

    id: str
    full_name: str
    username: str
    email: str


@dataclass(frozen=True, slots=True)
class AuthResult:
    """Outcome of a registration or login attempt.

    On success, ``user`` is populated (and ``token``/``expires_at`` for login).
    On failure, ``error`` holds a user-safe message and ``field_errors`` maps any
    per-field validation messages for inline display.
    """

    ok: bool
    user: AuthUser | None = None
    token: str = ""
    expires_at: str = ""
    error: str = ""
    field_errors: dict[str, str] | None = None
    backend_unavailable: bool = False


@dataclass(frozen=True, slots=True)
class Contribution:
    """An explainable contribution to a threat score."""

    feature: str
    detail: str
    weight: float


@dataclass(frozen=True, slots=True)
class SourceScoreDTO:
    """One intelligence source's contribution as seen by the UI."""

    source: str
    risk_percent: int
    confidence: float
    available: bool
    rationale: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The result of a URL scan (or an error)."""

    url: str = ""
    verdict: str = ""
    threat_score: float = 0.0
    confidence: float = 0.0
    risk_percent: int = 0
    category: str = "none"
    evidence_strength: float = 0.0
    blacklisted: bool = False
    blacklist_hit: bool = False
    contributions: tuple[Contribution, ...] = ()
    sources: tuple[SourceScoreDTO, ...] = ()
    scan_id: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        """Whether the scan succeeded."""
        return not self.error


@dataclass(frozen=True, slots=True)
class ThreatEntryDTO:
    """A blacklist entry as seen by the UI."""

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
    indicators: tuple[Contribution, ...] = ()


@dataclass(frozen=True, slots=True)
class ThreatStatus:
    """The outcome of a blacklist check."""

    blocked: bool
    threat: ThreatEntryDTO | None = None


@dataclass(frozen=True, slots=True)
class ThreatStatsDTO:
    """Aggregate blacklist statistics."""

    total_blacklisted: int = 0
    threats_blocked: int = 0
    high_risk_count: int = 0
    most_recent: str | None = None


@dataclass(frozen=True, slots=True)
class AuthMechanismDTO:
    """A single SPF/DKIM/DMARC result."""

    name: str
    status: str
    reason: str
    impact: str


@dataclass(frozen=True, slots=True)
class OverviewDTO:
    """Parsed email metadata."""

    from_display: str = ""
    from_address: str = ""
    to: tuple[str, ...] = ()
    cc: tuple[str, ...] = ()
    bcc: tuple[str, ...] = ()
    subject: str = ""
    date: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    mime_version: str = ""
    content_type: str = ""
    priority: str = ""


@dataclass(frozen=True, slots=True)
class SenderIntelDTO:
    """Sender investigation summary."""

    display_name: str = ""
    address: str = ""
    domain: str = ""
    reply_to: str = ""
    reply_to_mismatch: bool = False
    brand_impersonation: bool = False
    impersonation_detail: str = ""
    prior_scans: int = 0
    prior_malicious: int = 0


@dataclass(frozen=True, slots=True)
class AttachmentDTO:
    """Attachment metadata and risk."""

    filename: str
    extension: str
    size: int
    content_type: str
    sha256: str
    indicators: tuple[str, ...] = ()
    yara_scan: str = "not_available"
    malware_scan: str = "not_available"
    sandbox: str = "not_available"


@dataclass(frozen=True, slots=True)
class BodyDTO:
    """Email body views."""

    plain: str = ""
    html: str = ""
    raw: str = ""


@dataclass(frozen=True, slots=True)
class InvestigationDTO:
    """Analyst workflow metadata."""

    scan_id: str = ""
    status: str = "open"
    priority: str = "medium"
    tags: tuple[str, ...] = ()
    notes: str = ""


@dataclass(frozen=True, slots=True)
class MetricDTO:
    """A labelled metric card."""

    label: str
    value: str
    detail: str = ""
    tone: str = "neutral"


@dataclass(frozen=True, slots=True)
class TimelineEventDTO:
    """One SOC timeline entry."""

    timestamp: str
    kind: str
    severity: str
    title: str
    detail: str
    artifact_type: str = ""
    incident_id: str = ""
    campaign_id: str = ""


@dataclass(frozen=True, slots=True)
class IncidentSummaryDTO:
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


@dataclass(frozen=True, slots=True)
class CampaignSummaryDTO:
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
class HealthComponentDTO:
    """One platform component's health."""

    name: str
    status: str
    detail: str


@dataclass(frozen=True, slots=True)
class SocOverviewDTO:
    """The complete SOC operational picture."""

    threat_level: str = "Normal"
    risk_score: float = 0.0
    platform_status: str = "Unknown"
    generated_at: str = ""
    posture: tuple[MetricDTO, ...] = ()
    incident_metrics: tuple[MetricDTO, ...] = ()
    incident_queue: tuple[IncidentSummaryDTO, ...] = ()
    priority_distribution: tuple[tuple[str, int], ...] = ()
    campaign_metrics: tuple[MetricDTO, ...] = ()
    campaigns: tuple[CampaignSummaryDTO, ...] = ()
    threat_metrics: tuple[MetricDTO, ...] = ()
    top_malicious_urls: tuple[tuple[str, int], ...] = ()
    top_malicious_senders: tuple[tuple[str, int], ...] = ()
    threat_categories: tuple[tuple[str, int], ...] = ()
    artifact_distribution: tuple[tuple[str, int], ...] = ()
    timeline: tuple[TimelineEventDTO, ...] = ()
    analytics: tuple[MetricDTO, ...] = ()
    risk_distribution: tuple[tuple[str, int], ...] = ()
    detection_trend: tuple[tuple[str, int], ...] = ()
    analyst_activity: tuple[MetricDTO, ...] = ()
    recent_comments: tuple[tuple[str, str], ...] = ()
    health: tuple[HealthComponentDTO, ...] = ()
    error: str = ""

    @property
    def ok(self) -> bool:
        """Whether the overview loaded."""
        return not self.error


def _metrics(raw: list[dict[str, Any]]) -> tuple[MetricDTO, ...]:
    return tuple(
        MetricDTO(
            label=str(m["label"]),
            value=str(m["value"]),
            detail=str(m.get("detail", "")),
            tone=str(m.get("tone", "neutral")),
        )
        for m in raw
    )


def _pairs(raw: list[list[Any]]) -> tuple[tuple[str, int], ...]:
    return tuple((str(name), int(count)) for name, count in raw)


def _parse_soc(data: dict[str, Any]) -> SocOverviewDTO:
    return SocOverviewDTO(
        threat_level=str(data.get("threat_level", "Normal")),
        risk_score=float(data.get("risk_score", 0.0)),
        platform_status=str(data.get("platform_status", "Unknown")),
        generated_at=str(data.get("generated_at", "")),
        posture=_metrics(data.get("posture", [])),
        incident_metrics=_metrics(data.get("incident_metrics", [])),
        incident_queue=tuple(
            IncidentSummaryDTO(
                id=str(i["id"]),
                title=str(i["title"]),
                category=str(i["category"]),
                risk_percent=int(i["risk_percent"]),
                status=str(i["status"]),
                priority=str(i["priority"]),
                assignee=str(i["assignee"]),
                occurrences=int(i["occurrences"]),
                affected_users=int(i["affected_users"]),
                last_seen=str(i["last_seen"]),
            )
            for i in data.get("incident_queue", [])
        ),
        priority_distribution=_pairs(data.get("priority_distribution", [])),
        campaign_metrics=_metrics(data.get("campaign_metrics", [])),
        campaigns=tuple(
            CampaignSummaryDTO(
                id=str(c["id"]),
                name=str(c["name"]),
                category=str(c["category"]),
                risk_percent=int(c["risk_percent"]),
                occurrences=int(c["occurrences"]),
                affected_users=int(c["affected_users"]),
                first_seen=str(c["first_seen"]),
                last_seen=str(c["last_seen"]),
            )
            for c in data.get("campaigns", [])
        ),
        threat_metrics=_metrics(data.get("threat_metrics", [])),
        top_malicious_urls=_pairs(data.get("top_malicious_urls", [])),
        top_malicious_senders=_pairs(data.get("top_malicious_senders", [])),
        threat_categories=_pairs(data.get("threat_categories", [])),
        artifact_distribution=_pairs(data.get("artifact_distribution", [])),
        timeline=tuple(
            TimelineEventDTO(
                timestamp=str(e["timestamp"]),
                kind=str(e["kind"]),
                severity=str(e["severity"]),
                title=str(e["title"]),
                detail=str(e["detail"]),
                artifact_type=str(e.get("artifact_type", "")),
                incident_id=str(e.get("incident_id", "")),
                campaign_id=str(e.get("campaign_id", "")),
            )
            for e in data.get("timeline", [])
        ),
        analytics=_metrics(data.get("analytics", [])),
        risk_distribution=_pairs(data.get("risk_distribution", [])),
        detection_trend=_pairs(data.get("detection_trend", [])),
        analyst_activity=_metrics(data.get("analyst_activity", [])),
        recent_comments=tuple((str(a), str(b)) for a, b in data.get("recent_comments", [])),
        health=tuple(
            HealthComponentDTO(
                name=str(h["name"]), status=str(h["status"]), detail=str(h["detail"])
            )
            for h in data.get("health", [])
        ),
    )


@dataclass(frozen=True, slots=True)
class ArtifactDTO:
    """A correlatable observable."""

    kind: str
    value: str
    label: str


@dataclass(frozen=True, slots=True)
class IncidentEventDTO:
    """An investigation history entry."""

    label: str
    detail: str
    occurred_at: str


@dataclass(frozen=True, slots=True)
class IncidentDTO:
    """A correlated incident."""

    id: str = ""
    title: str = ""
    category: str = "none"
    risk_percent: int = 0
    status: str = "open"
    priority: str = "medium"
    assignee: str = ""
    tags: tuple[str, ...] = ()
    campaign_id: str = ""
    scan_ids: tuple[str, ...] = ()
    occurrences: int = 0
    affected_users: tuple[str, ...] = ()
    artifacts: tuple[ArtifactDTO, ...] = ()
    events: tuple[IncidentEventDTO, ...] = ()
    first_seen: str = ""
    last_seen: str = ""


@dataclass(frozen=True, slots=True)
class CampaignDTO:
    """A discovered campaign."""

    id: str = ""
    name: str = ""
    category: str = "none"
    risk_percent: int = 0
    occurrences: int = 0
    affected_users: tuple[str, ...] = ()
    artifacts: tuple[ArtifactDTO, ...] = ()
    first_seen: str = ""
    last_seen: str = ""


def _parse_artifacts(raw: list[dict[str, Any]]) -> tuple[ArtifactDTO, ...]:
    return tuple(
        ArtifactDTO(kind=str(a["kind"]), value=str(a["value"]), label=str(a["label"])) for a in raw
    )


def _parse_incident(data: dict[str, Any]) -> IncidentDTO:
    return IncidentDTO(
        id=str(data.get("id", "")),
        title=str(data.get("title", "")),
        category=str(data.get("category", "none")),
        risk_percent=int(data.get("risk_percent", 0)),
        status=str(data.get("status", "open")),
        priority=str(data.get("priority", "medium")),
        assignee=str(data.get("assignee", "")),
        tags=tuple(str(t) for t in data.get("tags", [])),
        campaign_id=str(data.get("campaign_id", "")),
        scan_ids=tuple(str(s) for s in data.get("scan_ids", [])),
        occurrences=int(data.get("occurrences", 0)),
        affected_users=tuple(str(u) for u in data.get("affected_users", [])),
        artifacts=_parse_artifacts(data.get("artifacts", [])),
        events=tuple(
            IncidentEventDTO(
                label=str(e["label"]),
                detail=str(e["detail"]),
                occurred_at=str(e["occurred_at"]),
            )
            for e in data.get("events", [])
        ),
        first_seen=str(data.get("first_seen", "")),
        last_seen=str(data.get("last_seen", "")),
    )


def _parse_campaign(data: dict[str, Any]) -> CampaignDTO:
    return CampaignDTO(
        id=str(data.get("id", "")),
        name=str(data.get("name", "")),
        category=str(data.get("category", "none")),
        risk_percent=int(data.get("risk_percent", 0)),
        occurrences=int(data.get("occurrences", 0)),
        affected_users=tuple(str(u) for u in data.get("affected_users", [])),
        artifacts=_parse_artifacts(data.get("artifacts", [])),
        first_seen=str(data.get("first_seen", "")),
        last_seen=str(data.get("last_seen", "")),
    )


@dataclass(frozen=True, slots=True)
class EmbeddedUrlDTO:
    """An embedded-URL result within an email scan."""

    url: str
    verdict: str
    risk_percent: int
    blacklisted: bool


@dataclass(frozen=True, slots=True)
class FileIndicatorsDTO:
    """Extracted indicators of compromise from a file."""

    urls: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    ipv4_addresses: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()
    total: int = 0


@dataclass(frozen=True, slots=True)
class FileOverviewDTO:
    """Parsed file metadata."""

    filename: str = ""
    size: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    file_kind: str = ""
    detected_mime: str = ""
    declared_mime: str = ""
    extension: str = ""
    entropy: float = 0.0
    entropy_descriptor: str = ""
    mime_mismatch: bool = False
    double_extension: bool = False
    is_executable: bool = False
    is_script: bool = False
    is_archive: bool = False


@dataclass(frozen=True, slots=True)
class FileScanResult:
    """The result of a file scan (or an error)."""

    filename: str = ""
    verdict: str = ""
    category: str = "none"
    threat_score: float = 0.0
    confidence: float = 0.0
    risk_percent: int = 0
    evidence_strength: float = 0.0
    malicious: bool = False
    size: int = 0
    sha256: str = ""
    file_kind: str = ""
    entropy: float = 0.0
    indicator_count: int = 0
    url_count: int = 0
    malicious_url_count: int = 0
    contributions: tuple[Contribution, ...] = ()
    sources: tuple[SourceScoreDTO, ...] = ()
    urls: tuple[EmbeddedUrlDTO, ...] = ()
    indicators: FileIndicatorsDTO | None = None
    overview: FileOverviewDTO | None = None
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    correlation_rationale: str = ""
    scan_id: str = ""
    investigation: InvestigationSummary | None = None
    error: str = ""

    @property
    def ok(self) -> bool:
        """Whether the scan succeeded."""
        return not self.error


@dataclass(frozen=True, slots=True)
class EmailScanResult:
    """The result of an email scan (or an error)."""

    sender: str = ""
    subject: str = ""
    verdict: str = ""
    category: str = "none"
    threat_score: float = 0.0
    confidence: float = 0.0
    risk_percent: int = 0
    evidence_strength: float = 0.0
    malicious: bool = False
    url_count: int = 0
    malicious_url_count: int = 0
    contributions: tuple[Contribution, ...] = ()
    sources: tuple[SourceScoreDTO, ...] = ()
    urls: tuple[EmbeddedUrlDTO, ...] = ()
    authentication: tuple[AuthMechanismDTO, ...] = ()
    overview: OverviewDTO | None = None
    sender_intel: SenderIntelDTO | None = None
    attachments: tuple[AttachmentDTO, ...] = ()
    body: BodyDTO | None = None
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    correlation_rationale: str = ""
    scan_id: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        """Whether the scan succeeded."""
        return not self.error


def _parse_email_scan(data: dict[str, Any]) -> EmailScanResult:
    return EmailScanResult(
        sender=str(data.get("sender", "")),
        subject=str(data.get("subject", "")),
        verdict=str(data.get("verdict", "")),
        category=str(data.get("category", "none")),
        threat_score=float(data.get("threat_score", 0.0)),
        confidence=float(data.get("confidence", 0.0)),
        risk_percent=int(data.get("risk_percent", 0)),
        evidence_strength=float(data.get("evidence_strength", 0.0)),
        malicious=bool(data.get("malicious", False)),
        url_count=int(data.get("url_count", 0)),
        malicious_url_count=int(data.get("malicious_url_count", 0)),
        contributions=tuple(
            Contribution(
                feature=str(c["feature"]),
                detail=str(c["detail"]),
                weight=float(c["weight"]),
            )
            for c in data.get("contributions", [])
        ),
        sources=tuple(
            SourceScoreDTO(
                source=str(s["source"]),
                risk_percent=int(s["risk_percent"]),
                confidence=float(s["confidence"]),
                available=bool(s["available"]),
                rationale=str(s["rationale"]),
            )
            for s in data.get("sources", [])
        ),
        urls=tuple(
            EmbeddedUrlDTO(
                url=str(u["url"]),
                verdict=str(u["verdict"]),
                risk_percent=int(u["risk_percent"]),
                blacklisted=bool(u["blacklisted"]),
            )
            for u in data.get("urls", [])
        ),
        authentication=tuple(
            AuthMechanismDTO(
                name=str(a["name"]),
                status=str(a["status"]),
                reason=str(a["reason"]),
                impact=str(a["impact"]),
            )
            for a in data.get("authentication", [])
        ),
        overview=_parse_overview(data.get("overview")),
        sender_intel=_parse_sender_intel(data.get("sender_intel")),
        attachments=tuple(
            AttachmentDTO(
                filename=str(a["filename"]),
                extension=str(a["extension"]),
                size=int(a["size"]),
                content_type=str(a["content_type"]),
                sha256=str(a["sha256"]),
                indicators=tuple(str(i) for i in a.get("indicators", [])),
                yara_scan=str(a.get("yara_scan", "not_available")),
                malware_scan=str(a.get("malware_scan", "not_available")),
                sandbox=str(a.get("sandbox", "not_available")),
            )
            for a in data.get("attachments", [])
        ),
        body=_parse_body(data.get("body")),
        incident_id=str(data.get("incident_id", "")),
        incident_title=str(data.get("incident_title", "")),
        campaign_name=str(data.get("campaign_name", "")),
        correlation_rationale=str(data.get("correlation_rationale", "")),
        scan_id=str(data.get("id", "")),
    )


def _parse_overview(data: dict[str, Any] | None) -> OverviewDTO | None:
    if not data:
        return None
    return OverviewDTO(
        from_display=str(data.get("from_display", "")),
        from_address=str(data.get("from_address", "")),
        to=tuple(str(x) for x in data.get("to", [])),
        cc=tuple(str(x) for x in data.get("cc", [])),
        bcc=tuple(str(x) for x in data.get("bcc", [])),
        subject=str(data.get("subject", "")),
        date=str(data.get("date", "")),
        reply_to=str(data.get("reply_to", "")),
        return_path=str(data.get("return_path", "")),
        message_id=str(data.get("message_id", "")),
        mime_version=str(data.get("mime_version", "")),
        content_type=str(data.get("content_type", "")),
        priority=str(data.get("priority", "")),
    )


def _parse_sender_intel(data: dict[str, Any] | None) -> SenderIntelDTO | None:
    if not data:
        return None
    return SenderIntelDTO(
        display_name=str(data.get("display_name", "")),
        address=str(data.get("address", "")),
        domain=str(data.get("domain", "")),
        reply_to=str(data.get("reply_to", "")),
        reply_to_mismatch=bool(data.get("reply_to_mismatch", False)),
        brand_impersonation=bool(data.get("brand_impersonation", False)),
        impersonation_detail=str(data.get("impersonation_detail", "")),
        prior_scans=int(data.get("prior_scans", 0)),
        prior_malicious=int(data.get("prior_malicious", 0)),
    )


def _parse_body(data: dict[str, Any] | None) -> BodyDTO | None:
    if not data:
        return None
    return BodyDTO(
        plain=str(data.get("plain", "")),
        html=str(data.get("html", "")),
        raw=str(data.get("raw", "")),
    )


def _parse_evidence_node(raw: dict[str, Any]) -> EvidenceNode:
    """Reconstruct a (recursive) evidence-tree node from its DTO."""
    return EvidenceNode(
        label=str(raw.get("label", "")),
        detail=str(raw.get("detail", "")),
        risk=float(raw.get("risk", 0.0)),
        confidence=float(raw.get("confidence", 0.0)),
        technique_id=str(raw.get("technique_id", "")),
        recommendation=str(raw.get("recommendation", "")),
        tone=str(raw.get("tone", "neutral")),
        children=tuple(_parse_evidence_node(c) for c in raw.get("children", [])),
    )


def _parse_investigation_summary(raw: dict[str, Any] | None) -> InvestigationSummary | None:
    """Reconstruct the unified :class:`InvestigationSummary` from its DTO."""
    if not raw:
        return None
    return InvestigationSummary(
        investigation_id=str(raw.get("investigation_id", "")),
        artifact_id=str(raw.get("artifact_id", "")),
        artifact_type=str(raw.get("artifact_type", "")),
        status=str(raw.get("status", "open")),
        created_at=str(raw.get("created_at", "")),
        updated_at=str(raw.get("updated_at", "")),
        analysis_duration_ms=float(raw.get("analysis_duration_ms", 0.0)),
        verdict=str(raw.get("verdict", "")),
        severity=str(raw.get("severity", "info")),
        confidence=float(raw.get("confidence", 0.0)),
        confidence_source=str(raw.get("confidence_source", "")),
        category=str(raw.get("category", "none")),
        risk_percent=int(raw.get("risk_percent", 0)),
        evidence_strength=float(raw.get("evidence_strength", 0.0)),
        malicious=bool(raw.get("malicious", False)),
        timeline=tuple(
            InvestigationEvent(
                timestamp=str(e.get("timestamp", "")),
                kind=EventKind(str(e.get("kind", "analysis_started"))),
                source=str(e.get("source", "")),
                description=str(e.get("description", "")),
                detail=str(e.get("detail", "")),
            )
            for e in raw.get("timeline", [])
        ),
        evidence_tree=tuple(_parse_evidence_node(n) for n in raw.get("evidence_tree", [])),
        metadata=tuple(
            MetadataField(
                label=str(m.get("label", "")),
                value=str(m.get("value", "")),
                category=str(m.get("category", "general")),
            )
            for m in raw.get("metadata", [])
        ),
        recommendations=tuple(str(r) for r in raw.get("recommendations", [])),
        technique_ids=tuple(str(t) for t in raw.get("technique_ids", [])),
        relationships=tuple(
            (str(r[0]), str(r[1]), str(r[2]), str(r[3]), float(r[4]))
            for r in raw.get("relationships", [])
            if len(r) >= 5  # noqa: PLR2004 - relationship tuple arity
        ),
        provider_diagnostics=tuple(
            (str(d[0]), str(d[1]), float(d[2]), int(d[3]))
            for d in raw.get("provider_diagnostics", [])
            if len(d) >= 4  # noqa: PLR2004 - diagnostics tuple arity
        ),
        threat_history=tuple(str(h) for h in raw.get("threat_history", [])),
        performance={str(k): float(v) for k, v in raw.get("performance", {}).items()},
    )


def _parse_file_scan(data: dict[str, Any]) -> FileScanResult:
    overview_raw = data.get("overview")
    indicators_raw = data.get("indicators")
    overview = (
        FileOverviewDTO(
            filename=str(overview_raw.get("filename", "")),
            size=int(overview_raw.get("size", 0)),
            sha256=str(overview_raw.get("sha256", "")),
            sha1=str(overview_raw.get("sha1", "")),
            md5=str(overview_raw.get("md5", "")),
            file_kind=str(overview_raw.get("file_kind", "")),
            detected_mime=str(overview_raw.get("detected_mime", "")),
            declared_mime=str(overview_raw.get("declared_mime", "")),
            extension=str(overview_raw.get("extension", "")),
            entropy=float(overview_raw.get("entropy", 0.0)),
            entropy_descriptor=str(overview_raw.get("entropy_descriptor", "")),
            mime_mismatch=bool(overview_raw.get("mime_mismatch", False)),
            double_extension=bool(overview_raw.get("double_extension", False)),
            is_executable=bool(overview_raw.get("is_executable", False)),
            is_script=bool(overview_raw.get("is_script", False)),
            is_archive=bool(overview_raw.get("is_archive", False)),
        )
        if overview_raw
        else None
    )
    indicators = (
        FileIndicatorsDTO(
            urls=tuple(str(x) for x in indicators_raw.get("urls", [])),
            domains=tuple(str(x) for x in indicators_raw.get("domains", [])),
            ipv4_addresses=tuple(str(x) for x in indicators_raw.get("ipv4_addresses", [])),
            emails=tuple(str(x) for x in indicators_raw.get("emails", [])),
            hashes=tuple(str(x) for x in indicators_raw.get("hashes", [])),
            total=int(indicators_raw.get("total", 0)),
        )
        if indicators_raw
        else None
    )
    return FileScanResult(
        filename=str(data.get("filename", "")),
        verdict=str(data.get("verdict", "")),
        category=str(data.get("category", "none")),
        threat_score=float(data.get("threat_score", 0.0)),
        confidence=float(data.get("confidence", 0.0)),
        risk_percent=int(data.get("risk_percent", 0)),
        evidence_strength=float(data.get("evidence_strength", 0.0)),
        malicious=bool(data.get("malicious", False)),
        size=int(data.get("size", 0)),
        sha256=str(data.get("sha256", "")),
        file_kind=str(data.get("file_kind", "")),
        entropy=float(data.get("entropy", 0.0)),
        indicator_count=int(data.get("indicator_count", 0)),
        url_count=int(data.get("url_count", 0)),
        malicious_url_count=int(data.get("malicious_url_count", 0)),
        contributions=tuple(
            Contribution(
                feature=str(c["feature"]),
                detail=str(c["detail"]),
                weight=float(c["weight"]),
            )
            for c in data.get("contributions", [])
        ),
        sources=tuple(
            SourceScoreDTO(
                source=str(s["source"]),
                risk_percent=int(s["risk_percent"]),
                confidence=float(s["confidence"]),
                available=bool(s["available"]),
                rationale=str(s["rationale"]),
            )
            for s in data.get("sources", [])
        ),
        urls=tuple(
            EmbeddedUrlDTO(
                url=str(u["url"]),
                verdict=str(u["verdict"]),
                risk_percent=int(u["risk_percent"]),
                blacklisted=bool(u["blacklisted"]),
            )
            for u in data.get("urls", [])
        ),
        indicators=indicators,
        overview=overview,
        incident_id=str(data.get("incident_id", "")),
        incident_title=str(data.get("incident_title", "")),
        campaign_name=str(data.get("campaign_name", "")),
        correlation_rationale=str(data.get("correlation_rationale", "")),
        scan_id=str(data.get("id", "")),
        investigation=_parse_investigation_summary(data.get("investigation")),
    )


def _parse_investigation(data: dict[str, Any]) -> InvestigationDTO:
    return InvestigationDTO(
        scan_id=str(data.get("scan_id", "")),
        status=str(data.get("status", "open")),
        priority=str(data.get("priority", "medium")),
        tags=tuple(str(t) for t in data.get("tags", [])),
        notes=str(data.get("notes", "")),
    )


def _parse_auth_user(data: dict[str, Any]) -> AuthUser:
    return AuthUser(
        id=str(data.get("id", "")),
        full_name=str(data.get("full_name", "")),
        username=str(data.get("username", "")),
        email=str(data.get("email", "")),
    )


def _detail_message(response: httpx.Response, fallback: str) -> str:
    """Extract a user-safe ``detail`` message from an error response."""
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        return fallback
    if isinstance(detail, str) and detail:
        return detail
    if isinstance(detail, dict):
        message = detail.get("message")
        if isinstance(message, str) and message:
            return message
    return fallback


def _parse_gmail_status(data: dict[str, Any]) -> GmailStatusDTO:
    return GmailStatusDTO(
        connected=bool(data.get("connected", False)),
        email_address=str(data.get("email_address", "")),
        scope=str(data.get("scope", "")),
        read_only=bool(data.get("read_only", True)),
        processed_messages=int(data.get("processed_messages", 0) or 0),
        last_synced_at=str(data.get("last_synced_at", "")),
    )


def _parse_gmail_sync(data: dict[str, Any]) -> GmailSyncDTO:
    return GmailSyncDTO(
        retrieved=int(data.get("retrieved", 0) or 0),
        analyzed=int(data.get("analyzed", 0) or 0),
        duplicates=int(data.get("duplicates", 0) or 0),
        malicious=int(data.get("malicious", 0) or 0),
        suspicious=int(data.get("suspicious", 0) or 0),
        benign=int(data.get("benign", 0) or 0),
        errors=int(data.get("errors", 0) or 0),
        unsupported=int(data.get("unsupported", 0) or 0),
        transient=int(data.get("transient", 0) or 0),
        failed=int(data.get("failed", 0) or 0),
        synced_at=str(data.get("synced_at", "")),
        ok=True,
    )


def _parse_gmail_message(data: dict[str, Any]) -> GmailMessageDTO:
    return GmailMessageDTO(
        message_id=str(data.get("message_id", "")),
        thread_id=str(data.get("thread_id", "")),
        sender=str(data.get("sender", "")),
        subject=str(data.get("subject", "")),
        received_at=str(data.get("received_at", "")),
        snippet=str(data.get("snippet", "")),
        status=str(data.get("status", "analyzed")),
        risk_band=str(data.get("risk_band", "unanalyzed")),
        verdict=str(data.get("verdict", "")),
        risk_percent=int(data.get("risk_percent", 0) or 0),
        confidence=float(data.get("confidence", 0.0) or 0.0),
        scan_id=str(data.get("scan_id", "")),
    )


def _parse_gmail_url(data: dict[str, Any]) -> GmailUrlDTO:
    return GmailUrlDTO(
        url=str(data.get("url", "")),
        verdict=str(data.get("verdict", "untrusted")),
        risk_percent=int(data.get("risk_percent", 0) or 0),
        blacklisted=bool(data.get("blacklisted", False)),
    )


def _parse_gmail_preview(data: dict[str, Any] | None) -> GmailPreviewDTO | None:
    if not isinstance(data, dict):
        return None
    return GmailPreviewDTO(
        from_display=str(data.get("from_display", "")),
        from_address=str(data.get("from_address", "")),
        to=tuple(str(x) for x in data.get("to", []) or []),
        cc=tuple(str(x) for x in data.get("cc", []) or []),
        subject=str(data.get("subject", "")),
        date=str(data.get("date", "")),
        reply_to=str(data.get("reply_to", "")),
        plain_body=str(data.get("plain_body", "")),
        urls=tuple(_parse_gmail_url(u) for u in data.get("urls", []) or []),
        attachments=tuple(str(a) for a in data.get("attachments", []) or []),
        error=str(data.get("error", "")),
    )


def _parse_gmail_message_detail(data: dict[str, Any]) -> GmailMessageDetailDTO:
    message = _parse_gmail_message(data.get("message", {}) or {})
    return GmailMessageDetailDTO(
        message=message,
        category=str(data.get("category", "")),
        evidence_strength=float(data.get("evidence_strength", 0.0) or 0.0),
        url_count=int(data.get("url_count", 0) or 0),
        malicious_url_count=int(data.get("malicious_url_count", 0) or 0),
        evidence=tuple(
            GmailEvidenceDTO(
                feature=str(e.get("feature", "")),
                detail=str(e.get("detail", "")),
                weight=float(e.get("weight", 0.0) or 0.0),
            )
            for e in data.get("evidence", []) or []
        ),
        sources=tuple(
            GmailSourceDTO(
                source=str(s.get("source", "")),
                risk_percent=int(s.get("risk_percent", 0) or 0),
                confidence=float(s.get("confidence", 0.0) or 0.0),
                available=bool(s.get("available", False)),
                rationale=str(s.get("rationale", "")),
            )
            for s in data.get("sources", []) or []
        ),
        urls=tuple(_parse_gmail_url(u) for u in data.get("urls", []) or []),
        iocs=tuple(str(i) for i in data.get("iocs", []) or []),
        recommendations=tuple(str(r) for r in data.get("recommendations", []) or []),
        incident_id=str(data.get("incident_id", "")),
        incident_title=str(data.get("incident_title", "")),
        campaign_name=str(data.get("campaign_name", "")),
        artifact_id=str(data.get("artifact_id", "")),
        preview=_parse_gmail_preview(data.get("preview")),
        analysis_error=str(data.get("analysis_error", "")),
        ok=True,
    )


def _parse_auth_error(response: httpx.Response) -> AuthResult:
    """Translate a non-success auth response into a user-safe :class:`AuthResult`."""
    try:
        detail = response.json().get("detail", {})
    except (ValueError, AttributeError):
        detail = {}
    if isinstance(detail, dict):
        message = str(detail.get("message", "")) or "Registration could not be completed."
        fields = detail.get("fields")
        field_errors = (
            {str(k): str(v) for k, v in fields.items()} if isinstance(fields, dict) else None
        )
    else:
        message = str(detail) or "Registration could not be completed."
        field_errors = None
    if response.status_code == HTTPStatus.CONFLICT:
        message = "An AEGIS+ account already exists for this installation."
    return AuthResult(ok=False, error=message, field_errors=field_errors)


def _parse_scan(data: dict[str, Any]) -> ScanResult:
    contributions = tuple(
        Contribution(
            feature=str(c["feature"]),
            detail=str(c["detail"]),
            weight=float(c["weight"]),
        )
        for c in data.get("contributions", [])
    )
    sources = tuple(
        SourceScoreDTO(
            source=str(s["source"]),
            risk_percent=int(s["risk_percent"]),
            confidence=float(s["confidence"]),
            available=bool(s["available"]),
            rationale=str(s["rationale"]),
        )
        for s in data.get("sources", [])
    )
    return ScanResult(
        url=str(data.get("url", "")),
        verdict=str(data.get("verdict", "")),
        threat_score=float(data.get("threat_score", 0.0)),
        confidence=float(data.get("confidence", 0.0)),
        risk_percent=int(data.get("risk_percent", 0)),
        category=str(data.get("category", "none")),
        evidence_strength=float(data.get("evidence_strength", 0.0)),
        blacklisted=bool(data.get("blacklisted", False)),
        blacklist_hit=bool(data.get("blacklist_hit", False)),
        contributions=contributions,
        sources=sources,
        scan_id=str(data.get("id", "")),
    )


def _parse_threat(data: dict[str, Any]) -> ThreatEntryDTO:
    indicators = tuple(
        Contribution(feature=str(i["feature"]), detail=str(i["detail"]), weight=0.0)
        for i in data.get("indicators", [])
    )
    return ThreatEntryDTO(
        hash=str(data.get("hash", "")),
        url=str(data.get("url", "")),
        artifact_type=str(data.get("artifact_type", "url")),
        verdict=str(data.get("verdict", "")),
        risk_percent=int(data.get("risk_percent", 0)),
        confidence=float(data.get("confidence", 0.0)),
        first_detected=str(data.get("first_detected", "")),
        last_detected=str(data.get("last_detected", "")),
        detection_count=int(data.get("detection_count", 0)),
        blocked=bool(data.get("blocked", False)),
        block_source=str(data.get("block_source", "")),
        indicators=indicators,
    )


def _parse_node_view(raw: dict[str, Any]) -> GraphNodeView:
    return GraphNodeView(
        node_id=str(raw.get("node_id", "")),
        node_type=str(raw.get("node_type", "")),
        label=str(raw.get("label", "")),
        tone=str(raw.get("tone", "neutral")),
        risk_percent=int(raw.get("risk_percent", 0)),
        degree=int(raw.get("degree", 0)),
        labels=tuple(str(x) for x in raw.get("labels", [])),
        metadata={str(k): str(v) for k, v in raw.get("metadata", {}).items()},
    )


def _parse_edge_view(raw: dict[str, Any]) -> GraphEdgeView:
    return GraphEdgeView(
        edge_id=str(raw.get("edge_id", "")),
        source_id=str(raw.get("source_id", "")),
        target_id=str(raw.get("target_id", "")),
        relationship=str(raw.get("relationship", "")),
        confidence=float(raw.get("confidence", 1.0)),
        provenance=str(raw.get("provenance", "")),
        timestamp=str(raw.get("timestamp", "")),
    )


def _parse_graph_view(data: dict[str, Any]) -> GraphView:
    return GraphView(
        root_id=str(data.get("root_id", "")),
        nodes=tuple(_parse_node_view(n) for n in data.get("nodes", [])),
        edges=tuple(_parse_edge_view(e) for e in data.get("edges", [])),
        truncated=bool(data.get("truncated", False)),
    )


def _parse_path_view(data: dict[str, Any]) -> GraphPathView:
    return GraphPathView(
        source_id=str(data.get("source_id", "")),
        target_id=str(data.get("target_id", "")),
        found=bool(data.get("found", False)),
        length=int(data.get("length", 0)),
        nodes=tuple(_parse_node_view(n) for n in data.get("nodes", [])),
        edges=tuple(_parse_edge_view(e) for e in data.get("edges", [])),
    )


def _parse_pairs(raw: list[list[Any]]) -> tuple[tuple[str, int], ...]:
    return tuple((str(item[0]), int(item[1])) for item in raw if len(item) >= 2)  # noqa: PLR2004


def _parse_snapshot_view(data: dict[str, Any]) -> GraphSnapshotView:
    return GraphSnapshotView(
        node_count=int(data.get("node_count", 0)),
        edge_count=int(data.get("edge_count", 0)),
        duplicate_suppressions=int(data.get("duplicate_suppressions", 0)),
        node_type_counts=_parse_pairs(data.get("node_type_counts", [])),
        relationship_type_counts=_parse_pairs(data.get("relationship_type_counts", [])),
    )


_PAIR = 2


def _str_list(values: Any) -> tuple[str, ...]:
    return tuple(str(v) for v in values) if isinstance(values, list) else ()


def _parse_analytics_overview(data: dict[str, Any]) -> AnalyticsOverview:
    return AnalyticsOverview(
        threat_priorities=tuple(
            ThreatScore(
                artifact_id=str(s.get("artifact_id", "")),
                label=str(s.get("label", "")),
                severity=float(s.get("severity", 0.0)),
                confidence=float(s.get("confidence", 0.0)),
                exposure=float(s.get("exposure", 0.0)),
                blast_radius=int(s.get("blast_radius", 0)),
                priority=float(s.get("priority", 0.0)),
                analyst_urgency=float(s.get("analyst_urgency", 0.0)),
                rationale=_str_list(s.get("rationale", [])),
            )
            for s in data.get("threat_priorities", [])
        ),
        emerging_campaigns=tuple(
            CampaignIntelligence(
                campaign_id=str(c.get("campaign_id", "")),
                label=str(c.get("label", "")),
                artifact_count=int(c.get("artifact_count", 0)),
                ioc_count=int(c.get("ioc_count", 0)),
                infrastructure_count=int(c.get("infrastructure_count", 0)),
                shared_ioc_score=float(c.get("shared_ioc_score", 0.0)),
                rationale=_str_list(c.get("rationale", [])),
            )
            for c in data.get("emerging_campaigns", [])
        ),
        ioc_trends=tuple(
            IOCIntelligence(
                ioc_id=str(i.get("ioc_id", "")),
                label=str(i.get("label", "")),
                frequency=int(i.get("frequency", 0)),
                prevalence=float(i.get("prevalence", 0.0)),
                confidence=float(i.get("confidence", 0.0)),
                aging_days=float(i.get("aging_days", 0.0)),
                rationale=_str_list(i.get("rationale", [])),
            )
            for i in data.get("ioc_trends", [])
        ),
        infrastructure_reuse=tuple(
            InfrastructureCluster(
                infra_id=str(c.get("infra_id", "")),
                infra_type=str(c.get("infra_type", "")),
                infra_label=str(c.get("infra_label", "")),
                member_ids=_str_list(c.get("member_ids", [])),
                rationale=_str_list(c.get("rationale", [])),
            )
            for c in data.get("infrastructure_reuse", [])
        ),
        critical_attack_paths=tuple(
            CompromisePath(
                source_id=str(p.get("source_id", "")),
                target_id=str(p.get("target_id", "")),
                node_ids=_str_list(p.get("node_ids", [])),
                hops=int(p.get("hops", 0)),
                rationale=_str_list(p.get("rationale", [])),
            )
            for p in data.get("critical_attack_paths", [])
        ),
        threat_distribution=tuple(
            (str(pair[0]), int(pair[1]))
            for pair in data.get("threat_distribution", [])
            if len(pair) == _PAIR
        ),
        recommendations=tuple(
            Recommendation(
                kind=str(r.get("kind", "")),
                title=str(r.get("title", "")),
                subject_id=str(r.get("subject_id", "")),
                subject_type=str(r.get("subject_type", "")),
                priority=float(r.get("priority", 0.0)),
                rationale=_str_list(r.get("rationale", [])),
            )
            for r in data.get("recommendations", [])
        ),
    )


def _parse_overlay(data: dict[str, Any]) -> GraphOverlay:
    return GraphOverlay(
        nodes=tuple(
            NodeOverlay(
                node_id=str(n.get("node_id", "")),
                risk_percent=int(n.get("risk_percent", 0)),
                is_critical=bool(n.get("is_critical", False)),
                campaign_id=str(n.get("campaign_id", "")),
                cluster_id=str(n.get("cluster_id", "")),
                on_attack_path=bool(n.get("on_attack_path", False)),
                propagation_rank=int(n.get("propagation_rank", 0)),
            )
            for n in data.get("nodes", [])
        ),
        attack_path_ids=_str_list(data.get("attack_path_ids", [])),
        critical_ids=_str_list(data.get("critical_ids", [])),
        top_central=tuple(
            RankedNode(
                node_id=str(r.get("node_id", "")),
                node_type=str(r.get("node_type", "")),
                label=str(r.get("label", "")),
                score=float(r.get("score", 0.0)),
                degree=int(r.get("degree", 0)),
                risk_percent=int(r.get("risk_percent", 0)),
            )
            for r in data.get("top_central", [])
        ),
    )


def _parse_copilot_response(data: dict[str, Any]) -> CopilotResponse:
    meta = data.get("prompt_metadata", {}) or {}
    return CopilotResponse(
        answer=str(data.get("answer", "")),
        citations=tuple(
            Citation(
                kind=str(c.get("kind", "")),
                source_id=str(c.get("source_id", "")),
                label=str(c.get("label", "")),
                excerpt=str(c.get("excerpt", "")),
            )
            for c in data.get("citations", [])
        ),
        related=tuple(
            ContextItem(
                kind=str(r.get("kind", "")),
                source_id=str(r.get("source_id", "")),
                label=str(r.get("label", "")),
                summary=str(r.get("summary", "")),
            )
            for r in data.get("related", [])
        ),
        context_summary=_str_list(data.get("context_summary", [])),
        grounding_score=float(data.get("grounding_score", 0.0)),
        grounding_violations=tuple(
            GroundingViolation(
                reason=str(v.get("reason", "")),
                detail=str(v.get("detail", "")),
            )
            for v in data.get("grounding_violations", [])
        ),
        prompt_metadata=PromptMetadata(
            prompt_id=str(meta.get("prompt_id", "")),
            prompt_version=str(meta.get("prompt_version", "")),
            skill_id=str(meta.get("skill_id", "")),
            intent=str(meta.get("intent", "")),
            model_id=str(meta.get("model_id", "")),
            provider=str(meta.get("provider", "")),
            temperature=float(meta.get("temperature", 0.0)),
            timestamp=str(meta.get("timestamp", "")),
            context_item_count=int(meta.get("context_item_count", 0)),
            prompt_token_estimate=int(meta.get("prompt_token_estimate", 0)),
        ),
        session_id=str(data.get("session_id", "")),
        prompt_tokens=int(data.get("prompt_tokens", 0)),
        completion_tokens=int(data.get("completion_tokens", 0)),
        latency_ms=float(data.get("latency_ms", 0.0)),
        available=bool(data.get("available", True)),
    )


def _parse_stream_line(line: str) -> CopilotStreamEvent | None:
    """Parse one SSE ``data:`` line from the Copilot stream into an event."""
    stripped = line.strip()
    if not stripped or not stripped.startswith("data:"):
        return None
    body = stripped[len("data:") :].strip()
    if not body:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    kind = str(data.get("kind", ""))
    response = None
    raw_response = data.get("response")
    if isinstance(raw_response, dict):
        response = _parse_copilot_response(raw_response)
    return CopilotStreamEvent(
        kind=kind,
        text=str(data.get("text", "")),
        error=str(data.get("error", "")),
        response=response,
    )


def _parse_analytics(data: dict[str, Any]) -> GraphAnalyticsSummary:
    return GraphAnalyticsSummary(
        node_count=int(data.get("node_count", 0)),
        edge_count=int(data.get("edge_count", 0)),
        ioc_count=int(data.get("ioc_count", 0)),
        node_type_counts=_parse_pairs(data.get("node_type_counts", [])),
        relationship_type_counts=_parse_pairs(data.get("relationship_type_counts", [])),
        most_connected=tuple(
            ConnectedEntity(
                node=_parse_node_view(entity.get("node", {})),
                degree=int(entity.get("degree", 0)),
            )
            for entity in data.get("most_connected", [])
        ),
        largest_component_size=int(data.get("largest_component_size", 0)),
        component_count=int(data.get("component_count", 0)),
        reachable_from_top=int(data.get("reachable_from_top", 0)),
        density=float(data.get("density", 0.0)),
    )


def _parse_search(data: dict[str, Any]) -> GraphSearchResult:
    return GraphSearchResult(
        query=str(data.get("query", "")),
        focus_id=str(data.get("focus_id", "")),
        matches=tuple(_parse_node_view(n) for n in data.get("matches", [])),
    )


def _parse_selection(data: dict[str, Any]) -> GraphSelection:
    return GraphSelection(
        focus_id=str(data.get("focus_id", "")),
        neighbor_ids=tuple(str(x) for x in data.get("neighbor_ids", [])),
        edge_ids=tuple(str(x) for x in data.get("edge_ids", [])),
    )


class BackendClient:
    """A thin synchronous client for the embedded backend."""

    def __init__(self, base_url: str, *, timeout: float = 3.0) -> None:
        """Initialize the client.

        Args:
            base_url: The backend base URL (e.g. ``http://127.0.0.1:8137``).
            timeout: Per-request timeout in seconds.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._token = ""
        self._on_unauthorized: Callable[[], None] | None = None

    @property
    def base_url(self) -> str:
        """The backend base URL."""
        return self._base_url

    # --- authentication state -------------------------------------------

    def set_token(self, token: str) -> None:
        """Attach ``token`` as the bearer credential on subsequent requests."""
        self._token = token

    def clear_token(self) -> None:
        """Drop any stored bearer credential (used on logout/expiry)."""
        self._token = ""

    @property
    def has_token(self) -> bool:
        """Whether a bearer credential is currently held."""
        return bool(self._token)

    def set_unauthorized_handler(self, handler: Callable[[], None] | None) -> None:
        """Register a callback invoked when the backend returns 401.

        The UI uses this to route the analyst back to login on session expiry.
        The handler is invoked at most once per expiry detection; it must not
        raise.
        """
        self._on_unauthorized = handler

    def _auth_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = dict(extra or {})
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _note_unauthorized(self, response: httpx.Response) -> None:
        """Fire the unauthorized handler when a protected call is rejected."""
        if response.status_code == HTTPStatus.UNAUTHORIZED and self._on_unauthorized:
            self._on_unauthorized()

    def _get(self, path_or_url: str, **kwargs: Any) -> httpx.Response:
        kwargs["headers"] = self._auth_headers(kwargs.pop("headers", None))
        kwargs.setdefault("timeout", self._timeout)
        response = httpx.get(path_or_url, **kwargs)
        self._note_unauthorized(response)
        return response

    def _post(self, path_or_url: str, **kwargs: Any) -> httpx.Response:
        kwargs["headers"] = self._auth_headers(kwargs.pop("headers", None))
        kwargs.setdefault("timeout", self._timeout)
        response = httpx.post(path_or_url, **kwargs)
        self._note_unauthorized(response)
        return response

    def _put(self, path_or_url: str, **kwargs: Any) -> httpx.Response:
        kwargs["headers"] = self._auth_headers(kwargs.pop("headers", None))
        kwargs.setdefault("timeout", self._timeout)
        response = httpx.put(path_or_url, **kwargs)
        self._note_unauthorized(response)
        return response

    def _delete(self, path_or_url: str, **kwargs: Any) -> httpx.Response:
        kwargs["headers"] = self._auth_headers(kwargs.pop("headers", None))
        kwargs.setdefault("timeout", self._timeout)
        response = httpx.delete(path_or_url, **kwargs)
        self._note_unauthorized(response)
        return response

    def liveness(self) -> HealthResult:
        """Query the liveness endpoint."""
        return self._probe("/health", expect_key="status", expect_value="ok")

    def readiness(self) -> HealthResult:
        """Query the readiness endpoint (dependencies healthy)."""
        try:
            response = self._get(f"{self._base_url}/health/ready", timeout=self._timeout)
        except httpx.HTTPError as exc:
            return HealthResult(False, str(exc))
        if response.status_code == HTTPStatus.OK:
            return HealthResult(True, "ready")
        return HealthResult(False, f"HTTP {response.status_code}")

    def identity(self) -> dict[str, str]:
        """Return backend identity (name, version, status)."""
        try:
            response = self._get(f"{self._base_url}/", timeout=self._timeout)
            response.raise_for_status()
            data = response.json()
            return {k: str(v) for k, v in data.items()}
        except httpx.HTTPError:
            return {}

    # --- authentication --------------------------------------------------

    def auth_status(self) -> bool | None:
        """Whether a local account exists, or ``None`` if the backend is unreachable."""
        try:
            response = httpx.get(f"{self._base_url}/api/auth/status", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError:
            return None
        return bool(response.json().get("account_exists", False))

    def register(
        self,
        *,
        full_name: str,
        username: str,
        email: str,
        password: str,
        confirm_password: str,
    ) -> AuthResult:
        """Create the single local account."""
        payload = {
            "full_name": full_name,
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": confirm_password,
        }
        try:
            response = httpx.post(
                f"{self._base_url}/api/auth/register", json=payload, timeout=self._timeout
            )
        except httpx.HTTPError:
            return AuthResult(
                ok=False,
                backend_unavailable=True,
                error="Cannot reach the AEGIS+ backend. Please try again.",
            )
        if response.status_code == HTTPStatus.CREATED:
            return AuthResult(ok=True, user=_parse_auth_user(response.json().get("user", {})))
        return _parse_auth_error(response)

    def login(self, *, identifier: str, password: str) -> AuthResult:
        """Authenticate and, on success, store the session token on the client."""
        payload = {"identifier": identifier, "password": password}
        try:
            response = httpx.post(
                f"{self._base_url}/api/auth/login", json=payload, timeout=self._timeout
            )
        except httpx.HTTPError:
            return AuthResult(
                ok=False,
                backend_unavailable=True,
                error="Cannot reach the AEGIS+ backend. Please try again.",
            )
        if response.status_code == HTTPStatus.OK:
            body = response.json()
            self.set_token(str(body.get("token", "")))
            return AuthResult(
                ok=True,
                user=_parse_auth_user(body.get("user", {})),
                token=str(body.get("token", "")),
                expires_at=str(body.get("expires_at", "")),
            )
        if response.status_code == HTTPStatus.UNAUTHORIZED:
            return AuthResult(ok=False, error="Invalid username or password.")
        return _parse_auth_error(response)

    def current_user(self) -> AuthResult:
        """Return the current authenticated user for the stored token."""
        try:
            response = httpx.get(
                f"{self._base_url}/api/auth/me",
                headers=self._auth_headers(),
                timeout=self._timeout,
            )
        except httpx.HTTPError:
            return AuthResult(ok=False, backend_unavailable=True, error="Backend unavailable.")
        if response.status_code == HTTPStatus.OK:
            return AuthResult(ok=True, user=_parse_auth_user(response.json()))
        return AuthResult(ok=False, error="Session expired.")

    def logout(self) -> None:
        """Invalidate the current session on the backend and drop the token."""
        token = self._token
        if token:
            with suppress(httpx.HTTPError):
                httpx.post(
                    f"{self._base_url}/api/auth/logout",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=self._timeout,
                )
        self.clear_token()

    # --- gmail connector -------------------------------------------------

    def gmail_status(self) -> GmailStatusDTO:
        """Fetch the current Gmail connection status."""
        try:
            response = self._get(f"{self._base_url}/api/gmail/status", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return GmailStatusDTO(connected=False, error=f"Could not load status: {exc}")
        return _parse_gmail_status(response.json())

    def gmail_connect(self, *, timeout: float = 240.0) -> GmailStatusDTO:
        """Run the Gmail OAuth connect flow (opens the system browser).

        Uses a long timeout because the user completes consent in their browser.
        """
        try:
            response = self._post(f"{self._base_url}/api/gmail/connect", timeout=timeout)
        except httpx.HTTPError as exc:
            return GmailStatusDTO(connected=False, error=f"Could not connect: {exc}")
        if response.status_code != HTTPStatus.OK:
            return GmailStatusDTO(
                connected=False,
                error=_detail_message(response, "Could not connect Gmail."),
            )
        return _parse_gmail_status(response.json())

    def gmail_disconnect(self) -> GmailStatusDTO:
        """Disconnect Gmail (clears tokens and sync state)."""
        try:
            response = self._post(f"{self._base_url}/api/gmail/disconnect", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return GmailStatusDTO(connected=False, error=f"Could not disconnect: {exc}")
        return _parse_gmail_status(response.json())

    def gmail_sync(
        self, *, max_messages: int | None = None, timeout: float = 120.0
    ) -> GmailSyncDTO:
        """Trigger a Gmail synchronization pass and return its statistics."""
        payload: dict[str, Any] = {}
        if max_messages is not None:
            payload["max_messages"] = max_messages
        try:
            response = self._post(f"{self._base_url}/api/gmail/sync", json=payload, timeout=timeout)
        except httpx.HTTPError as exc:
            return GmailSyncDTO(ok=False, error=f"Synchronization failed: {exc}")
        if response.status_code != HTTPStatus.OK:
            return GmailSyncDTO(
                ok=False,
                error=_detail_message(response, "Gmail synchronization could not complete."),
            )
        return _parse_gmail_sync(response.json())

    def gmail_messages(
        self, *, risk_filter: str = "all", search: str = ""
    ) -> tuple[GmailMessageDTO, ...]:
        """Fetch the analyst Gmail message list for the active account."""
        params = {"risk_filter": risk_filter, "search": search}
        try:
            response = self._get(
                f"{self._base_url}/api/gmail/messages", params=params, timeout=self._timeout
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return ()
        data = response.json()
        if not isinstance(data, list):
            return ()
        return tuple(_parse_gmail_message(item) for item in data)

    def gmail_message_detail(self, message_id: str) -> GmailMessageDetailDTO:
        """Fetch the full analyst detail for one Gmail message."""
        try:
            response = self._get(
                f"{self._base_url}/api/gmail/messages/{message_id}", timeout=self._timeout
            )
        except httpx.HTTPError as exc:
            return GmailMessageDetailDTO(
                message=GmailMessageDTO(message_id=message_id),
                ok=False,
                error=f"Could not load message: {exc}",
            )
        if response.status_code != HTTPStatus.OK:
            return GmailMessageDetailDTO(
                message=GmailMessageDTO(message_id=message_id),
                ok=False,
                error=_detail_message(response, "This message could not be loaded."),
            )
        return _parse_gmail_message_detail(response.json())

    def scan_url(self, url: str) -> ScanResult:
        """Submit a URL for analysis.

        Args:
            url: The URL to analyze.

        Returns:
            The parsed :class:`ScanResult`, or one carrying an ``error``.
        """
        try:
            response = self._post(
                f"{self._base_url}/api/url/scan",
                json={"url": url},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            return ScanResult(error=str(exc))
        if response.status_code == HTTPStatus.OK:
            return _parse_scan(response.json())
        if response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY:
            return ScanResult(error="Invalid URL")
        return ScanResult(error=f"HTTP {response.status_code}")

    def recent_scans(self, limit: int = 10) -> list[ScanResult]:
        """Return recent scans, newest first (empty on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/url/scans/recent",
                params={"limit": limit},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return []
        return [_parse_scan(item) for item in response.json()]

    def scan_email(self, content: str) -> EmailScanResult:
        """Analyze a raw email message through the backend."""
        try:
            response = self._post(
                f"{self._base_url}/api/email/scan",
                json={"content": content},
                timeout=self._timeout,
            )
            if response.status_code == _HTTP_UNPROCESSABLE:
                return EmailScanResult(error="Could not parse the email content.")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return EmailScanResult(error=f"Scan failed: {exc}")
        return _parse_email_scan(response.json())

    def get_email_scan(self, scan_id: str) -> EmailScanResult:
        """Fetch a persisted email scan by id (opens the investigation workspace)."""
        try:
            response = self._get(
                f"{self._base_url}/api/email/scans/{scan_id}", timeout=self._timeout
            )
            if response.status_code == HTTPStatus.NOT_FOUND:
                return EmailScanResult(error="This investigation is no longer available.")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return EmailScanResult(error=f"Could not load investigation: {exc}")
        return _parse_email_scan(response.json())

    def soc_overview(self) -> SocOverviewDTO:
        """Fetch the complete SOC operational picture in one request."""
        try:
            response = self._get(f"{self._base_url}/api/soc/overview", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return SocOverviewDTO(error=f"Could not load overview: {exc}")
        return _parse_soc(response.json())

    def list_incidents(self) -> list[IncidentDTO]:
        """Return correlated incidents, most recently seen first."""
        try:
            response = self._get(f"{self._base_url}/api/incidents", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError:
            return []
        return [_parse_incident(item) for item in response.json()]

    def list_campaigns(self) -> list[CampaignDTO]:
        """Return discovered campaigns, most recently seen first."""
        try:
            response = self._get(f"{self._base_url}/api/campaigns", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError:
            return []
        return [_parse_campaign(item) for item in response.json()]

    def relationships(self, kind: str, value: str) -> tuple[str, ...]:
        """Return relationship statements for one observable."""
        try:
            response = self._get(
                f"{self._base_url}/api/relationships",
                params={"kind": kind, "value": value},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return ()
        return tuple(str(s) for s in response.json().get("statements", []))

    def update_incident(
        self,
        incident_id: str,
        *,
        status: str | None = None,
        assignee: str | None = None,
        priority: str | None = None,
        tags: tuple[str, ...] | None = None,
        comment: str | None = None,
    ) -> IncidentDTO:
        """Apply an analyst workflow change to an incident."""
        payload: dict[str, Any] = {}
        if status is not None:
            payload["status"] = status
        if assignee is not None:
            payload["assignee"] = assignee
        if priority is not None:
            payload["priority"] = priority
        if tags is not None:
            payload["tags"] = list(tags)
        if comment is not None:
            payload["comment"] = comment
        try:
            response = self._put(
                f"{self._base_url}/api/incidents/{incident_id}/workflow",
                json=payload,
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return IncidentDTO(id=incident_id)
        return _parse_incident(response.json())

    def get_investigation(self, scan_id: str) -> InvestigationDTO:
        """Return the analyst investigation for a scan (defaults on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/email/investigations/{scan_id}",
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return InvestigationDTO(scan_id=scan_id)
        return _parse_investigation(response.json())

    def save_investigation(
        self,
        scan_id: str,
        *,
        status: str,
        priority: str,
        tags: tuple[str, ...],
        notes: str,
    ) -> InvestigationDTO:
        """Persist analyst workflow metadata for a scan."""
        try:
            response = self._put(
                f"{self._base_url}/api/email/investigations/{scan_id}",
                json={
                    "status": status,
                    "priority": priority,
                    "tags": list(tags),
                    "notes": notes,
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return InvestigationDTO(
                scan_id=scan_id, status=status, priority=priority, tags=tags, notes=notes
            )
        return _parse_investigation(response.json())

    def recent_email_scans(self, limit: int = 10) -> list[EmailScanResult]:
        """Return recent email scans, newest first (empty on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/email/scans/recent",
                params={"limit": limit},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return []
        return [_parse_email_scan(item) for item in response.json()]

    def scan_file(self, filename: str, data: bytes) -> FileScanResult:
        """Upload and analyze a file through the backend."""
        try:
            response = self._post(
                f"{self._base_url}/api/files/scan",
                files={"upload": (filename, data)},
                timeout=self._timeout,
            )
            if response.status_code == _HTTP_UNPROCESSABLE:
                return FileScanResult(error="The file could not be analyzed.")
            if response.status_code == _HTTP_TOO_LARGE:
                return FileScanResult(error="The file exceeds the upload limit.")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return FileScanResult(error=f"Scan failed: {exc}")
        return _parse_file_scan(response.json())

    def recent_file_scans(self, limit: int = 10) -> list[FileScanResult]:
        """Return recent file scans, newest first (empty on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/files/scans/recent",
                params={"limit": limit},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return []
        return [_parse_file_scan(item) for item in response.json()]

    def get_file_investigation(self, scan_id: str) -> InvestigationDTO:
        """Return the analyst investigation for a file scan (defaults on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/files/investigations/{scan_id}",
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return InvestigationDTO(scan_id=scan_id)
        return _parse_investigation(response.json())

    def save_file_investigation(
        self,
        scan_id: str,
        *,
        status: str,
        priority: str,
        tags: tuple[str, ...],
        notes: str,
    ) -> InvestigationDTO:
        """Persist analyst workflow metadata for a file scan."""
        try:
            response = self._put(
                f"{self._base_url}/api/files/investigations/{scan_id}",
                json={
                    "status": status,
                    "priority": priority,
                    "tags": list(tags),
                    "notes": notes,
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return InvestigationDTO(
                scan_id=scan_id, status=status, priority=priority, tags=tags, notes=notes
            )
        return _parse_investigation(response.json())

    def check_threat(self, url: str) -> ThreatStatus:
        """Check whether a URL is blacklisted (no side effects)."""
        return self._threat_check("check", url)

    def guard_open(self, url: str) -> ThreatStatus:
        """Guard an open attempt; the backend audits a prevented launch."""
        return self._threat_check("guard-open", url)

    def _threat_check(self, path: str, url: str) -> ThreatStatus:
        try:
            response = self._post(
                f"{self._base_url}/api/threats/{path}",
                json={"url": url},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return ThreatStatus(blocked=False)
        data = response.json()
        threat = data.get("threat")
        return ThreatStatus(
            blocked=bool(data.get("blocked", False)),
            threat=_parse_threat(threat) if threat else None,
        )

    def list_threats(self) -> list[ThreatEntryDTO]:
        """Return all blacklisted URLs, newest first (empty on error)."""
        try:
            response = self._get(f"{self._base_url}/api/threats", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError:
            return []
        return [_parse_threat(item) for item in response.json()]

    def threat_stats(self) -> ThreatStatsDTO:
        """Return aggregate blacklist statistics (defaults on error)."""
        try:
            response = self._get(f"{self._base_url}/api/threats/stats", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError:
            return ThreatStatsDTO()
        data = response.json()
        return ThreatStatsDTO(
            total_blacklisted=int(data.get("total_blacklisted", 0)),
            threats_blocked=int(data.get("threats_blocked", 0)),
            high_risk_count=int(data.get("high_risk_count", 0)),
            most_recent=data.get("most_recent"),
        )

    def graph_snapshot(self) -> GraphSnapshotView:
        """Return a point-in-time graph summary (defaults on error)."""
        try:
            response = self._get(f"{self._base_url}/api/graph/snapshot", timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError:
            return GraphSnapshotView()
        return _parse_snapshot_view(response.json())

    def graph_analytics(self, *, top: int = 5) -> GraphAnalyticsSummary:
        """Return lightweight graph analytics (defaults on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/graph/analytics",
                params={"top": top},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return GraphAnalyticsSummary()
        return _parse_analytics(response.json())

    def analytics_overview(self, *, top: int = 5) -> AnalyticsOverview:
        """Return the SOC advanced-analytics overview (defaults on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/analytics/overview",
                params={"top": top},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return AnalyticsOverview()
        return _parse_analytics_overview(response.json())

    def graph_overlay(self, *, top: int = 10) -> GraphOverlay:
        """Return the Graph Explorer overlay annotations (defaults on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/analytics/overlay",
                params={"top": top},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return GraphOverlay()
        return _parse_overlay(response.json())

    def graph_search(self, query: str, *, limit: int = 25) -> GraphSearchResult:
        """Search the graph and return matches with an auto-focus target."""
        try:
            response = self._get(
                f"{self._base_url}/api/graph/search",
                params={"q": query, "limit": limit},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return GraphSearchResult(query=query)
        return _parse_search(response.json())

    def graph_node(self, node_id: str) -> GraphNodeView | None:
        """Return a single node view, or ``None`` if missing or on error."""
        try:
            response = self._get(
                f"{self._base_url}/api/graph/nodes/{node_id}", timeout=self._timeout
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return None
        return _parse_node_view(response.json())

    def graph_neighbors(self, node_id: str, *, depth: int = 1) -> GraphView:
        """Return a node's neighbourhood up to ``depth`` hops (empty on error)."""
        return self._graph_view(f"/api/graph/nodes/{node_id}/neighbors", {"depth": depth}, node_id)

    def graph_selection(self, node_id: str) -> GraphSelection:
        """Return a lightweight selection descriptor (defaults on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/graph/nodes/{node_id}/selection", timeout=self._timeout
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return GraphSelection(focus_id=node_id)
        return _parse_selection(response.json())

    def graph_shortest_path(self, source_id: str, target_id: str) -> GraphPathView:
        """Return the shortest path between two nodes (not found on error)."""
        try:
            response = self._get(
                f"{self._base_url}/api/graph/path",
                params={"source": source_id, "target": target_id},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return GraphPathView(source_id=source_id, target_id=target_id)
        return _parse_path_view(response.json())

    def graph_shared_iocs(self, node_a_id: str, node_b_id: str) -> GraphView:
        """Return a view of two nodes and the IOCs they share (empty on error)."""
        return self._graph_view(
            "/api/graph/shared-iocs", {"a": node_a_id, "b": node_b_id}, node_a_id
        )

    def graph_investigation(self, root_id: str, *, depth: int = 2) -> GraphView:
        """Return the investigation subgraph from a root (empty on error)."""
        return self._graph_view(f"/api/graph/investigation/{root_id}", {"depth": depth}, root_id)

    def graph_incident(self, incident_id: str) -> GraphView:
        """Return the neighbourhood of an incident node (empty on error)."""
        return self._graph_view(f"/api/graph/incident/{incident_id}", {}, incident_id)

    def graph_campaign(self, campaign_id: str) -> GraphView:
        """Return the neighbourhood of a campaign node (empty on error)."""
        return self._graph_view(f"/api/graph/campaign/{campaign_id}", {}, campaign_id)

    def _graph_view(self, path: str, params: dict[str, Any], root_id: str) -> GraphView:
        try:
            response = self._get(f"{self._base_url}{path}", params=params, timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPError:
            return GraphView(root_id=root_id)
        return _parse_graph_view(response.json())

    def copilot_ask(
        self,
        question: str,
        *,
        session_id: str = "",
        artifact_id: str = "",
        incident_id: str = "",
        campaign_id: str = "",
        timeout: float | None = None,
    ) -> CopilotResponse:
        """Ask the AI Security Copilot a question (graceful default on error).

        The Copilot round-trip includes an LLM call, so this uses a longer
        timeout than the default probe timeout. On any transport error an
        unavailable response is returned so the UI degrades gracefully.
        """
        payload = {
            "question": question,
            "session_id": session_id,
            "artifact_id": artifact_id,
            "incident_id": incident_id,
            "campaign_id": campaign_id,
        }
        try:
            response = self._post(
                f"{self._base_url}/api/copilot/ask",
                json=payload,
                timeout=timeout if timeout is not None else 60.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return CopilotResponse(
                answer="The Copilot could not be reached.",
                session_id=session_id,
                grounding_score=0.0,
                available=False,
                grounding_violations=(
                    GroundingViolation(reason="transport_error", detail=str(exc)),
                ),
            )
        return _parse_copilot_response(response.json())

    def copilot_stream(
        self,
        question: str,
        *,
        session_id: str = "",
        artifact_id: str = "",
        incident_id: str = "",
        campaign_id: str = "",
        timeout: float | None = None,
    ) -> Iterator[CopilotStreamEvent]:
        """Stream a Copilot answer as incremental events.

        Yields ``token`` events (raw incremental text) followed by a terminal
        ``final`` event whose ``response`` is the grounding-validated answer, or
        an ``error`` event on failure. On any transport error a single ``error``
        event with a graceful fallback response is yielded, so the caller can
        fall back to the non-streaming path without special-casing exceptions.
        """
        payload = {
            "question": question,
            "session_id": session_id,
            "artifact_id": artifact_id,
            "incident_id": incident_id,
            "campaign_id": campaign_id,
        }
        try:
            with httpx.stream(
                "POST",
                f"{self._base_url}/api/copilot/ask/stream",
                json=payload,
                headers=self._auth_headers(),
                timeout=timeout if timeout is not None else 60.0,
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    event = _parse_stream_line(line)
                    if event is not None:
                        yield event
        except httpx.HTTPError as exc:
            fallback = CopilotResponse(
                answer="The Copilot could not be reached.",
                session_id=session_id,
                grounding_score=0.0,
                available=False,
                grounding_violations=(
                    GroundingViolation(reason="transport_error", detail=str(exc)),
                ),
            )
            yield CopilotStreamEvent(kind="error", error=str(exc), response=fallback)

    def copilot_update_focus(
        self,
        session_id: str,
        *,
        current_artifact_id: str = "",
        current_incident_id: str = "",
        active_campaign_id: str = "",
        recent_graph_selections: tuple[str, ...] = (),
    ) -> bool:
        """Record the analyst's current focus for a session (best effort)."""
        payload = {
            "current_artifact_id": current_artifact_id,
            "current_incident_id": current_incident_id,
            "active_campaign_id": active_campaign_id,
            "recent_graph_selections": list(recent_graph_selections),
        }
        try:
            response = self._post(
                f"{self._base_url}/api/copilot/session/{session_id}/focus",
                json=payload,
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return False
        return True

    def copilot_close_session(self, session_id: str) -> bool:
        """Close an in-memory Copilot session (best effort)."""
        try:
            response = self._delete(
                f"{self._base_url}/api/copilot/session/{session_id}",
                timeout=self._timeout,
            )
        except httpx.HTTPError:
            return False
        return response.status_code == HTTPStatus.NO_CONTENT

    def _probe(self, path: str, *, expect_key: str, expect_value: str) -> HealthResult:
        try:
            response = self._get(f"{self._base_url}{path}", timeout=self._timeout)
        except httpx.HTTPError as exc:
            return HealthResult(False, str(exc))
        if (
            response.status_code == HTTPStatus.OK
            and response.json().get(expect_key) == expect_value
        ):
            return HealthResult(True, "ok")
        return HealthResult(False, f"HTTP {response.status_code}")

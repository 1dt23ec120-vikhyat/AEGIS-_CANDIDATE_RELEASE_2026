"""Entity-to-row mappers.

Explicit translation between Core domain entities and ORM row models. Keeping
this mapping here - rather than on the entities - preserves domain purity: Core
entities remain free of ORM concerns, and persistence details stay in
infrastructure.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.constants import (
    ArtifactType,
    AuditOutcome,
    BlockSource,
    IncidentStatus,
    InvestigationPriority,
    InvestigationStatus,
)
from core.domain import EntityId, EvidenceSource, SourceScore, ThreatCategory, Verdict
from core.domain.analysis import FeatureContribution
from core.domain.correlation import ArtifactKind, ArtifactRef
from core.domain.file import Fingerprint, FingerprintSet
from core.entities import (
    AuditLog,
    Campaign,
    Configuration,
    EmailInvestigation,
    EmailScan,
    FileInvestigation,
    FileScan,
    Incident,
    IncidentComment,
    IncidentEvent,
    ThreatEntry,
    UrlScan,
)
from infrastructure.database.models import (
    AuditLogRow,
    CampaignRow,
    ConfigurationRow,
    EmailInvestigationRow,
    EmailScanRow,
    FileInvestigationRow,
    FileScanRow,
    IncidentRow,
    ThreatEntryRow,
    UrlScanRow,
)

# --- AuditLog ------------------------------------------------------------


def audit_log_to_row(entity: AuditLog) -> AuditLogRow:
    """Build a new row from an :class:`AuditLog` entity."""
    return AuditLogRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        action=entity.action,
        outcome=entity.outcome.value,
        actor=entity.actor,
        resource=entity.resource,
        context=dict(entity.context),
    )


def audit_log_to_entity(row: AuditLogRow) -> AuditLog:
    """Reconstruct an :class:`AuditLog` entity from a row."""
    return AuditLog(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        action=row.action,
        outcome=AuditOutcome(row.outcome),
        actor=row.actor,
        resource=row.resource,
        context=dict(row.context),
    )


def apply_audit_log_updates(row: AuditLogRow, entity: AuditLog) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.action = entity.action
    row.outcome = entity.outcome.value
    row.actor = entity.actor
    row.resource = entity.resource
    row.context = dict(entity.context)


# --- Configuration -------------------------------------------------------


def configuration_to_row(entity: Configuration) -> ConfigurationRow:
    """Build a new row from a :class:`Configuration` entity."""
    return ConfigurationRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        key=entity.key,
        value=entity.value,
        description=entity.description,
    )


def configuration_to_entity(row: ConfigurationRow) -> Configuration:
    """Reconstruct a :class:`Configuration` entity from a row."""
    return Configuration(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        key=row.key,
        value=row.value,
        description=row.description,
    )


def apply_configuration_updates(row: ConfigurationRow, entity: Configuration) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.key = entity.key
    row.value = entity.value
    row.description = entity.description


# --- UrlScan -------------------------------------------------------------


def _contributions_to_json(
    contributions: tuple[FeatureContribution, ...],
) -> list[dict[str, object]]:
    return [
        {
            "feature": c.feature,
            "detail": c.detail,
            "weight": c.weight,
            "triggered": c.triggered,
        }
        for c in contributions
    ]


def _contributions_from_json(
    raw: list[dict[str, object]],
) -> tuple[FeatureContribution, ...]:
    return tuple(
        FeatureContribution(
            feature=str(item["feature"]),
            detail=str(item["detail"]),
            weight=float(item["weight"]),  # type: ignore[arg-type]
            triggered=bool(item["triggered"]),
        )
        for item in raw
    )


def _sources_to_json(sources: tuple[SourceScore, ...]) -> list[dict[str, object]]:
    return [
        {
            "source": s.source.value,
            "risk": s.risk,
            "confidence": s.confidence,
            "available": s.available,
            "rationale": s.rationale,
        }
        for s in sources
    ]


def _sources_from_json(raw: list[dict[str, object]]) -> tuple[SourceScore, ...]:
    return tuple(
        SourceScore(
            source=EvidenceSource(item["source"]),
            risk=float(item["risk"]),  # type: ignore[arg-type]
            confidence=float(item["confidence"]),  # type: ignore[arg-type]
            available=bool(item["available"]),
            rationale=str(item["rationale"]),
        )
        for item in raw
    )


def url_scan_to_row(entity: UrlScan) -> UrlScanRow:
    """Build a new row from a :class:`UrlScan` entity."""
    return UrlScanRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        url=entity.url,
        verdict=entity.verdict.value,
        threat_score=entity.threat_score,
        confidence=entity.confidence,
        features=dict(entity.features),
        contributions=_contributions_to_json(entity.contributions),
        category=entity.category.value,
        evidence_strength=entity.evidence_strength,
        sources=_sources_to_json(entity.sources),
        actor=entity.actor,
    )


def url_scan_to_entity(row: UrlScanRow) -> UrlScan:
    """Reconstruct a :class:`UrlScan` entity from a row."""
    return UrlScan(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        url=row.url,
        verdict=Verdict(row.verdict),
        threat_score=row.threat_score,
        confidence=row.confidence,
        features=dict(row.features),
        contributions=_contributions_from_json(row.contributions),
        category=ThreatCategory(row.category),
        evidence_strength=row.evidence_strength,
        sources=_sources_from_json(row.sources),
        actor=row.actor,
    )


def apply_url_scan_updates(row: UrlScanRow, entity: UrlScan) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.url = entity.url
    row.verdict = entity.verdict.value
    row.threat_score = entity.threat_score
    row.confidence = entity.confidence
    row.features = dict(entity.features)
    row.contributions = _contributions_to_json(entity.contributions)
    row.category = entity.category.value
    row.evidence_strength = entity.evidence_strength
    row.sources = _sources_to_json(entity.sources)
    row.actor = entity.actor


# --- ThreatEntry ---------------------------------------------------------


def threat_entry_to_row(entity: ThreatEntry) -> ThreatEntryRow:
    """Build a new row from a :class:`ThreatEntry` entity."""
    return ThreatEntryRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        artifact_hash=entity.artifact_hash,
        artifact=entity.artifact,
        artifact_type=entity.artifact_type.value,
        verdict=entity.verdict.value,
        risk_score=entity.risk_score,
        confidence=entity.confidence,
        indicators=_contributions_to_json(entity.indicators),
        first_detected=entity.first_detected,
        last_detected=entity.last_detected,
        detection_count=entity.detection_count,
        blocked=entity.blocked,
        block_source=entity.block_source.value,
        notes=entity.notes,
    )


def threat_entry_to_entity(row: ThreatEntryRow) -> ThreatEntry:
    """Reconstruct a :class:`ThreatEntry` entity from a row."""
    return ThreatEntry(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        artifact_hash=row.artifact_hash,
        artifact=row.artifact,
        artifact_type=ArtifactType(row.artifact_type),
        verdict=Verdict(row.verdict),
        risk_score=row.risk_score,
        confidence=row.confidence,
        indicators=_contributions_from_json(row.indicators),
        first_detected=row.first_detected,
        last_detected=row.last_detected,
        detection_count=row.detection_count,
        blocked=row.blocked,
        block_source=BlockSource(row.block_source),
        notes=row.notes,
    )


def apply_threat_entry_updates(row: ThreatEntryRow, entity: ThreatEntry) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.verdict = entity.verdict.value
    row.risk_score = entity.risk_score
    row.confidence = entity.confidence
    row.indicators = _contributions_to_json(entity.indicators)
    row.last_detected = entity.last_detected
    row.detection_count = entity.detection_count
    row.blocked = entity.blocked
    row.block_source = entity.block_source.value
    row.notes = entity.notes


# --- EmailScan -----------------------------------------------------------


def email_scan_to_row(entity: EmailScan) -> EmailScanRow:
    """Build a new row from an :class:`EmailScan` entity."""
    return EmailScanRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        sender=entity.sender,
        subject=entity.subject,
        verdict=entity.verdict.value,
        threat_score=entity.threat_score,
        confidence=entity.confidence,
        category=entity.category.value,
        evidence_strength=entity.evidence_strength,
        contributions=_contributions_to_json(entity.contributions),
        sources=_sources_to_json(entity.sources),
        url_count=entity.url_count,
        malicious_url_count=entity.malicious_url_count,
        actor=entity.actor,
    )


def email_scan_to_entity(row: EmailScanRow) -> EmailScan:
    """Reconstruct an :class:`EmailScan` entity from a row."""
    return EmailScan(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        sender=row.sender,
        subject=row.subject,
        verdict=Verdict(row.verdict),
        threat_score=row.threat_score,
        confidence=row.confidence,
        category=ThreatCategory(row.category),
        evidence_strength=row.evidence_strength,
        contributions=_contributions_from_json(row.contributions),
        sources=_sources_from_json(row.sources),
        url_count=row.url_count,
        malicious_url_count=row.malicious_url_count,
        actor=row.actor,
    )


def apply_email_scan_updates(row: EmailScanRow, entity: EmailScan) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.verdict = entity.verdict.value
    row.threat_score = entity.threat_score
    row.confidence = entity.confidence
    row.category = entity.category.value
    row.evidence_strength = entity.evidence_strength
    row.contributions = _contributions_to_json(entity.contributions)
    row.sources = _sources_to_json(entity.sources)
    row.url_count = entity.url_count
    row.malicious_url_count = entity.malicious_url_count
    row.actor = entity.actor


# --- EmailInvestigation --------------------------------------------------


def email_investigation_to_row(entity: EmailInvestigation) -> EmailInvestigationRow:
    """Build a new row from an :class:`EmailInvestigation` entity."""
    return EmailInvestigationRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        scan_id=entity.scan_id,
        status=entity.status.value,
        priority=entity.priority.value,
        tags=list(entity.tags),
        notes=entity.notes,
    )


def email_investigation_to_entity(row: EmailInvestigationRow) -> EmailInvestigation:
    """Reconstruct an :class:`EmailInvestigation` entity from a row."""
    return EmailInvestigation(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        scan_id=row.scan_id,
        status=InvestigationStatus(row.status),
        priority=InvestigationPriority(row.priority),
        tags=tuple(row.tags),
        notes=row.notes,
    )


def apply_email_investigation_updates(
    row: EmailInvestigationRow, entity: EmailInvestigation
) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.status = entity.status.value
    row.priority = entity.priority.value
    row.tags = list(entity.tags)
    row.notes = entity.notes


# --- FileScan ------------------------------------------------------------


def _fingerprints_to_json(fingerprints: FingerprintSet) -> dict[str, str]:
    return fingerprints.as_dict()


def _fingerprints_from_json(raw: dict[str, Any] | None) -> FingerprintSet:
    items = raw or {}
    return FingerprintSet(
        fingerprints=tuple(
            Fingerprint(algorithm=str(algo), value=str(value)) for algo, value in items.items()
        )
    )


def file_scan_to_row(entity: FileScan) -> FileScanRow:
    """Build a new row from a :class:`FileScan` entity (byte-free)."""
    return FileScanRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        filename=entity.filename,
        size=entity.size,
        sha256=entity.fingerprints.sha256,
        fingerprints=_fingerprints_to_json(entity.fingerprints),
        file_kind=entity.file_kind,
        detected_mime=entity.detected_mime,
        entropy=entity.entropy,
        verdict=entity.verdict.value,
        threat_score=entity.threat_score,
        confidence=entity.confidence,
        category=entity.category.value,
        evidence_strength=entity.evidence_strength,
        contributions=_contributions_to_json(entity.contributions),
        sources=_sources_to_json(entity.sources),
        indicator_count=entity.indicator_count,
        url_count=entity.url_count,
        malicious_url_count=entity.malicious_url_count,
        actor=entity.actor,
    )


def file_scan_to_entity(row: FileScanRow) -> FileScan:
    """Reconstruct a :class:`FileScan` entity from a row."""
    return FileScan(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        filename=row.filename,
        size=row.size,
        fingerprints=_fingerprints_from_json(row.fingerprints),
        file_kind=row.file_kind,
        detected_mime=row.detected_mime,
        entropy=row.entropy,
        verdict=Verdict(row.verdict),
        threat_score=row.threat_score,
        confidence=row.confidence,
        category=ThreatCategory(row.category),
        evidence_strength=row.evidence_strength,
        contributions=_contributions_from_json(row.contributions),
        sources=_sources_from_json(row.sources),
        indicator_count=row.indicator_count,
        url_count=row.url_count,
        malicious_url_count=row.malicious_url_count,
        actor=row.actor,
    )


def apply_file_scan_updates(row: FileScanRow, entity: FileScan) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.verdict = entity.verdict.value
    row.threat_score = entity.threat_score
    row.confidence = entity.confidence
    row.category = entity.category.value
    row.evidence_strength = entity.evidence_strength
    row.contributions = _contributions_to_json(entity.contributions)
    row.sources = _sources_to_json(entity.sources)
    row.indicator_count = entity.indicator_count
    row.url_count = entity.url_count
    row.malicious_url_count = entity.malicious_url_count
    row.actor = entity.actor


# --- FileInvestigation ---------------------------------------------------


def file_investigation_to_row(entity: FileInvestigation) -> FileInvestigationRow:
    """Build a new row from a :class:`FileInvestigation` entity."""
    return FileInvestigationRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        scan_id=entity.scan_id,
        status=entity.status.value,
        priority=entity.priority.value,
        tags=list(entity.tags),
        notes=entity.notes,
    )


def file_investigation_to_entity(row: FileInvestigationRow) -> FileInvestigation:
    """Reconstruct a :class:`FileInvestigation` entity from a row."""
    return FileInvestigation(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        scan_id=row.scan_id,
        status=InvestigationStatus(row.status),
        priority=InvestigationPriority(row.priority),
        tags=tuple(row.tags),
        notes=row.notes,
    )


def apply_file_investigation_updates(row: FileInvestigationRow, entity: FileInvestigation) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.status = entity.status.value
    row.priority = entity.priority.value
    row.tags = list(entity.tags)
    row.notes = entity.notes


# --- Campaign / Incident -------------------------------------------------


def _artifacts_to_json(artifacts: tuple[ArtifactRef, ...]) -> list[dict[str, Any]]:
    return [{"kind": ref.kind.value, "value": ref.value} for ref in artifacts]


def _artifacts_from_json(raw: list[dict[str, Any]] | None) -> tuple[ArtifactRef, ...]:
    return tuple(
        ArtifactRef(kind=ArtifactKind(item["kind"]), value=str(item["value"]))
        for item in (raw or [])
    )


def campaign_to_row(entity: Campaign) -> CampaignRow:
    """Build a new row from a :class:`Campaign` entity."""
    return CampaignRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        name=entity.name,
        category=entity.category.value,
        risk_score=entity.risk_score,
        artifacts=_artifacts_to_json(entity.artifacts),
        occurrences=entity.occurrences,
        affected_users=list(entity.affected_users),
        first_seen=entity.first_seen,
        last_seen=entity.last_seen,
    )


def campaign_to_entity(row: CampaignRow) -> Campaign:
    """Reconstruct a :class:`Campaign` entity from a row."""
    return Campaign(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        name=row.name,
        category=ThreatCategory(row.category),
        risk_score=row.risk_score,
        artifacts=_artifacts_from_json(row.artifacts),
        occurrences=row.occurrences,
        affected_users=tuple(row.affected_users),
        first_seen=row.first_seen,
        last_seen=row.last_seen,
    )


def apply_campaign_updates(row: CampaignRow, entity: Campaign) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.name = entity.name
    row.category = entity.category.value
    row.risk_score = entity.risk_score
    row.artifacts = _artifacts_to_json(entity.artifacts)
    row.occurrences = entity.occurrences
    row.affected_users = list(entity.affected_users)
    row.last_seen = entity.last_seen


def incident_to_row(entity: Incident) -> IncidentRow:
    """Build a new row from an :class:`Incident` entity."""
    return IncidentRow(
        id=entity.id.value,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        title=entity.title,
        category=entity.category.value,
        risk_score=entity.risk_score,
        status=entity.status.value,
        priority=entity.priority.value,
        artifacts=_artifacts_to_json(entity.artifacts),
        scan_ids=list(entity.scan_ids),
        campaign_id=entity.campaign_id,
        assignee=entity.assignee,
        tags=list(entity.tags),
        comments=_comments_to_json(entity.comments),
        events=_events_to_json(entity.events),
        occurrences=entity.occurrences,
        affected_users=list(entity.affected_users),
        first_seen=entity.first_seen,
        last_seen=entity.last_seen,
    )


def incident_to_entity(row: IncidentRow) -> Incident:
    """Reconstruct an :class:`Incident` entity from a row."""
    return Incident(
        entity_id=EntityId(row.id),
        created_at=row.created_at,
        updated_at=row.updated_at,
        title=row.title,
        category=ThreatCategory(row.category),
        risk_score=row.risk_score,
        status=IncidentStatus(row.status),
        priority=InvestigationPriority(row.priority),
        artifacts=_artifacts_from_json(row.artifacts),
        scan_ids=tuple(row.scan_ids),
        campaign_id=row.campaign_id,
        assignee=row.assignee,
        tags=tuple(row.tags),
        comments=_comments_from_json(row.comments),
        events=_events_from_json(row.events),
        occurrences=row.occurrences,
        affected_users=tuple(row.affected_users),
        first_seen=row.first_seen,
        last_seen=row.last_seen,
    )


def apply_incident_updates(row: IncidentRow, entity: Incident) -> None:
    """Copy mutable fields from an entity onto an existing row."""
    row.updated_at = entity.updated_at
    row.title = entity.title
    row.category = entity.category.value
    row.risk_score = entity.risk_score
    row.status = entity.status.value
    row.priority = entity.priority.value
    row.artifacts = _artifacts_to_json(entity.artifacts)
    row.scan_ids = list(entity.scan_ids)
    row.campaign_id = entity.campaign_id
    row.assignee = entity.assignee
    row.tags = list(entity.tags)
    row.comments = _comments_to_json(entity.comments)
    row.events = _events_to_json(entity.events)
    row.occurrences = entity.occurrences
    row.affected_users = list(entity.affected_users)
    row.last_seen = entity.last_seen


def _comments_to_json(comments: tuple[IncidentComment, ...]) -> list[dict[str, Any]]:
    return [
        {
            "author": c.author,
            "body": c.body,
            "created_at": c.created_at.isoformat(),
        }
        for c in comments
    ]


def _comments_from_json(raw: list[dict[str, Any]] | None) -> tuple[IncidentComment, ...]:
    return tuple(
        IncidentComment(
            author=str(item["author"]),
            body=str(item["body"]),
            created_at=datetime.fromisoformat(str(item["created_at"])),
        )
        for item in (raw or [])
    )


def _events_to_json(events: tuple[IncidentEvent, ...]) -> list[dict[str, Any]]:
    return [
        {
            "label": e.label,
            "detail": e.detail,
            "occurred_at": e.occurred_at.isoformat(),
        }
        for e in events
    ]


def _events_from_json(raw: list[dict[str, Any]] | None) -> tuple[IncidentEvent, ...]:
    return tuple(
        IncidentEvent(
            label=str(item["label"]),
            detail=str(item["detail"]),
            occurred_at=datetime.fromisoformat(str(item["occurred_at"])),
        )
        for item in (raw or [])
    )

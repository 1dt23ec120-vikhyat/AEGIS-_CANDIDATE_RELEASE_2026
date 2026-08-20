"""Application intelligence events.

Immutable, typed event value objects that decouple intelligence producers from
downstream consumers. Every event carries a deterministic ``event_id``, a typed
``event_type``, a UTC timestamp, a ``correlation_id`` linking it to an
investigation chain, the originating ``source``, an ``artifact_id``, and a
typed ``payload`` containing the event-specific data.

New event types are added by subclassing :class:`IntelligenceEvent` with a new
``event_type`` literal — no handler registration or bus change required.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """The taxonomy of intelligence events."""

    ARTIFACT_ANALYZED = "artifact_analyzed"
    IOC_EXTRACTED = "ioc_extracted"
    THREAT_MATCHED = "threat_matched"
    THREAT_RECORDED = "threat_recorded"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    CAMPAIGN_CREATED = "campaign_created"
    CAMPAIGN_UPDATED = "campaign_updated"
    INVESTIGATION_COMPLETED = "investigation_completed"
    INTELLIGENCE_REPORT_GENERATED = "intelligence_report_generated"
    PROVIDER_STARTED = "provider_started"
    PROVIDER_COMPLETED = "provider_completed"
    PROVIDER_FAILED = "provider_failed"
    RELATIONSHIP_DISCOVERED = "relationship_discovered"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _event_id() -> str:
    return str(uuid.uuid4())


@dataclass(frozen=True, slots=True)
class IntelligenceEvent:
    """Base application event.

    Every intelligence event carries these fields. The ``payload`` dict holds
    the event-specific data so the bus and its subscribers do not need to know
    every concrete event type at compile time — new event types are additive.
    """

    event_type: EventType
    source: str
    artifact_id: str = ""
    correlation_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=_event_id)
    timestamp: str = field(default_factory=_now)


# ---------------------------------------------------------------------------
# Convenience constructors — one per event type
# ---------------------------------------------------------------------------


def artifact_analyzed(
    *,
    source: str,
    artifact_id: str,
    artifact_type: str,
    verdict: str,
    risk_score: float,
    category: str,
    correlation_id: str = "",
) -> IntelligenceEvent:
    """An artifact has been fully analyzed."""
    return IntelligenceEvent(
        event_type=EventType.ARTIFACT_ANALYZED,
        source=source,
        artifact_id=artifact_id,
        correlation_id=correlation_id,
        payload={
            "artifact_type": artifact_type,
            "verdict": verdict,
            "risk_score": risk_score,
            "category": category,
        },
    )


def ioc_extracted(
    *,
    source: str,
    artifact_id: str,
    ioc_count: int,
    correlation_id: str = "",
) -> IntelligenceEvent:
    """IOCs were extracted from an artifact."""
    return IntelligenceEvent(
        event_type=EventType.IOC_EXTRACTED,
        source=source,
        artifact_id=artifact_id,
        correlation_id=correlation_id,
        payload={"ioc_count": ioc_count},
    )


def threat_matched(
    *,
    source: str,
    artifact_id: str,
    threat_id: str = "",
    correlation_id: str = "",
) -> IntelligenceEvent:
    """An artifact matched an existing threat intelligence entry."""
    return IntelligenceEvent(
        event_type=EventType.THREAT_MATCHED,
        source=source,
        artifact_id=artifact_id,
        correlation_id=correlation_id,
        payload={"threat_id": threat_id},
    )


def threat_recorded(
    *,
    source: str,
    artifact_id: str,
    artifact_type: str,
    correlation_id: str = "",
) -> IntelligenceEvent:
    """A new threat entry was recorded in the blacklist."""
    return IntelligenceEvent(
        event_type=EventType.THREAT_RECORDED,
        source=source,
        artifact_id=artifact_id,
        correlation_id=correlation_id,
        payload={"artifact_type": artifact_type},
    )


def incident_created(
    *,
    source: str,
    incident_id: str,
    incident_title: str,
    artifact_id: str = "",
    correlation_id: str = "",
) -> IntelligenceEvent:
    """A new incident was opened from a detection."""
    return IntelligenceEvent(
        event_type=EventType.INCIDENT_CREATED,
        source=source,
        artifact_id=artifact_id,
        correlation_id=correlation_id,
        payload={"incident_id": incident_id, "incident_title": incident_title},
    )


def campaign_created(
    *,
    source: str,
    campaign_id: str,
    campaign_name: str,
    correlation_id: str = "",
) -> IntelligenceEvent:
    """A new campaign was created from correlated detections."""
    return IntelligenceEvent(
        event_type=EventType.CAMPAIGN_CREATED,
        source=source,
        correlation_id=correlation_id,
        payload={"campaign_id": campaign_id, "campaign_name": campaign_name},
    )


def provider_started(
    *, provider_name: str, version: str, artifact_type: str, artifact_id: str = ""
) -> IntelligenceEvent:
    """A provider began executing."""
    return IntelligenceEvent(
        event_type=EventType.PROVIDER_STARTED,
        source=provider_name,
        artifact_id=artifact_id,
        payload={"version": version, "artifact_type": artifact_type},
    )


def provider_completed(
    *,
    provider_name: str,
    version: str,
    execution_ms: float,
    evidence_count: int,
    artifact_id: str = "",
) -> IntelligenceEvent:
    """A provider finished executing successfully."""
    return IntelligenceEvent(
        event_type=EventType.PROVIDER_COMPLETED,
        source=provider_name,
        artifact_id=artifact_id,
        payload={
            "version": version,
            "execution_ms": execution_ms,
            "evidence_count": evidence_count,
        },
    )


def provider_failed(
    *, provider_name: str, version: str, error: str, artifact_id: str = ""
) -> IntelligenceEvent:
    """A provider failed during execution."""
    return IntelligenceEvent(
        event_type=EventType.PROVIDER_FAILED,
        source=provider_name,
        artifact_id=artifact_id,
        payload={"version": version, "error": error},
    )


def relationship_discovered(
    *,
    source: str,
    source_id: str,
    source_type: str,
    target_id: str,
    target_type: str,
    relationship: str,
    correlation_id: str = "",
) -> IntelligenceEvent:
    """A relationship between two artifacts was discovered."""
    return IntelligenceEvent(
        event_type=EventType.RELATIONSHIP_DISCOVERED,
        source=source,
        correlation_id=correlation_id,
        payload={
            "source_id": source_id,
            "source_type": source_type,
            "target_id": target_id,
            "target_type": target_type,
            "relationship": relationship,
        },
    )


def intelligence_report_generated(
    *,
    source: str,
    artifact_id: str,
    verdict: str,
    severity: str,
    duration_ms: float,
    correlation_id: str = "",
) -> IntelligenceEvent:
    """A unified intelligence report was generated."""
    return IntelligenceEvent(
        event_type=EventType.INTELLIGENCE_REPORT_GENERATED,
        source=source,
        artifact_id=artifact_id,
        correlation_id=correlation_id,
        payload={
            "verdict": verdict,
            "severity": severity,
            "duration_ms": duration_ms,
        },
    )


def investigation_completed(
    *,
    source: str,
    investigation_id: str,
    artifact_id: str = "",
    status: str = "",
    correlation_id: str = "",
) -> IntelligenceEvent:
    """An analyst investigation reached a recorded state."""
    return IntelligenceEvent(
        event_type=EventType.INVESTIGATION_COMPLETED,
        source=source,
        artifact_id=artifact_id,
        correlation_id=correlation_id,
        payload={
            "investigation_id": investigation_id,
            "status": status,
        },
    )

"""Intelligence event publisher — the single publishing seam.

The live intelligence pipeline turns analysis results into intelligence events on
the internal bus, where the already-subscribed :class:`GraphBuilder` (and
``EventHistory``) consume them. To avoid duplicating publisher logic across the
URL, email, and file services, **all** event construction lives here: each service
supplies its extracted facts and calls one method. Publishing is best-effort — a
failure is recorded and logged but never propagates into an analysis result.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.domain.events import (
    IntelligenceEvent,
    artifact_analyzed,
    campaign_created,
    incident_created,
    investigation_completed,
    ioc_extracted,
    relationship_discovered,
    threat_recorded,
)
from core.interfaces.event_bus import IEventBus
from core.interfaces.logger import ILogger

# Relationship target as (target_id, target_type, relationship).
RelatedEntity = tuple[str, str, str]

_MALICIOUS_VERDICTS = frozenset({"phishing", "malicious"})


def _is_malicious(verdict: str) -> bool:
    return verdict.lower() in _MALICIOUS_VERDICTS


class IntelligencePublisher:
    """Publishes intelligence events for the live pipeline (single seam)."""

    def __init__(self, bus: IEventBus, logger: ILogger) -> None:
        """Initialize the publisher.

        Args:
            bus: The internal event bus to publish onto.
            logger: Injected logger (bound to a pipeline context).
        """
        self._bus = bus
        self._logger = logger
        self._published = 0
        self._failures = 0
        self._by_type: dict[str, int] = {}

    # --- publishing API --------------------------------------------------

    def analysis_completed(  # noqa: PLR0913 - a wide but single publishing entry point
        self,
        *,
        source: str,
        artifact_id: str,
        artifact_type: str,
        verdict: str,
        risk_score: float,
        category: str,
        iocs: Iterable[str] = (),
        ioc_count: int = 0,
        related: Iterable[RelatedEntity] = (),
        malicious: bool | None = None,
        correlation_id: str = "",
    ) -> None:
        """Publish the events describing a completed artifact analysis.

        Emits ``artifact_analyzed`` always; ``ioc_extracted`` when any IOCs are
        reported (via ``iocs`` or a bare ``ioc_count``) plus one
        ``relationship_discovered`` per enumerated IOC; a
        ``relationship_discovered`` per entry in ``related``; and
        ``threat_recorded`` when the verdict is malicious.
        """
        self._emit(
            artifact_analyzed(
                source=source,
                artifact_id=artifact_id,
                artifact_type=artifact_type,
                verdict=verdict,
                risk_score=risk_score,
                category=category,
                correlation_id=correlation_id,
            )
        )
        ioc_list = [ioc for ioc in iocs if ioc]
        total_iocs = len(ioc_list) if ioc_list else ioc_count
        if total_iocs > 0:
            self._emit(
                ioc_extracted(
                    source=source,
                    artifact_id=artifact_id,
                    ioc_count=total_iocs,
                    correlation_id=correlation_id,
                )
            )
        for ioc in ioc_list:
            self._emit(
                relationship_discovered(
                    source=source,
                    source_id=artifact_id,
                    source_type=artifact_type,
                    target_id=ioc,
                    target_type="ioc",
                    relationship="shares_ioc",
                    correlation_id=correlation_id,
                )
            )
        for target_id, target_type, relationship in related:
            if not target_id:
                continue
            self._emit(
                relationship_discovered(
                    source=source,
                    source_id=artifact_id,
                    source_type=artifact_type,
                    target_id=target_id,
                    target_type=target_type,
                    relationship=relationship,
                    correlation_id=correlation_id,
                )
            )
        is_threat = malicious if malicious is not None else _is_malicious(verdict)
        if is_threat:
            self._emit(
                threat_recorded(
                    source=source,
                    artifact_id=artifact_id,
                    artifact_type=artifact_type,
                    correlation_id=correlation_id,
                )
            )

    def incident_opened(
        self, *, source: str, incident_id: str, title: str, artifact_id: str = ""
    ) -> None:
        """Publish an incident-created event."""
        self._emit(
            incident_created(
                source=source,
                incident_id=incident_id,
                incident_title=title,
                artifact_id=artifact_id,
            )
        )

    def campaign_observed(self, *, source: str, campaign_id: str, name: str) -> None:
        """Publish a campaign-created event."""
        self._emit(campaign_created(source=source, campaign_id=campaign_id, campaign_name=name))

    def investigation_recorded(
        self, *, source: str, investigation_id: str, artifact_id: str = "", status: str = ""
    ) -> None:
        """Publish an investigation-completed event."""
        self._emit(
            investigation_completed(
                source=source,
                investigation_id=investigation_id,
                artifact_id=artifact_id,
                status=status,
            )
        )

    # --- observability ---------------------------------------------------

    def metrics(self) -> dict[str, float]:
        """Publisher observability: totals and per-type counts."""
        metrics: dict[str, float] = {
            "events_published": float(self._published),
            "publish_failures": float(self._failures),
        }
        for event_type, count in self._by_type.items():
            metrics[f"type.{event_type}"] = float(count)
        return metrics

    # --- internals -------------------------------------------------------

    def _emit(self, event: IntelligenceEvent) -> None:
        """Publish one event; never let a failure escape into analysis."""
        try:
            self._bus.publish(event)
            self._published += 1
            key = event.event_type.value
            self._by_type[key] = self._by_type.get(key, 0) + 1
        except Exception:
            self._failures += 1
            self._logger.exception("Failed to publish {} event", event.event_type.value)

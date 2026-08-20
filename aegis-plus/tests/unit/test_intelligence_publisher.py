"""Tests for the IntelligencePublisher — the single publishing seam (M10)."""

from __future__ import annotations

import pytest

from core.domain.events import EventType, IntelligenceEvent
from core.interfaces.event_bus import EventHandler, IEventBus
from services.pipeline import IntelligencePublisher


class _RecordingBus(IEventBus):
    """A minimal bus that records published events."""

    def __init__(self) -> None:
        self.events: list[IntelligenceEvent] = []

    def publish(self, event: IntelligenceEvent) -> None:
        self.events.append(event)

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:  # pragma: no cover
        raise NotImplementedError

    def subscriber_count(self, event_type: EventType | None = None) -> int:
        return 0

    def types(self) -> list[EventType]:
        return [e.event_type for e in self.events]


class _ExplodingBus(_RecordingBus):
    def publish(self, event: IntelligenceEvent) -> None:
        raise RuntimeError("bus down")


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
    def bind(self, **k: object) -> _FakeLogger:
        return self


def _publisher(bus: IEventBus) -> IntelligencePublisher:
    return IntelligencePublisher(bus, _FakeLogger())


def test_benign_analysis_publishes_only_artifact() -> None:
    bus = _RecordingBus()
    _publisher(bus).analysis_completed(
        source="url-analysis",
        artifact_id="http://safe.example",
        artifact_type="url",
        verdict="benign",
        risk_score=0.1,
        category="none",
    )
    assert bus.types() == [EventType.ARTIFACT_ANALYZED]


def test_malicious_with_iocs_publishes_full_chain() -> None:
    bus = _RecordingBus()
    _publisher(bus).analysis_completed(
        source="url-analysis",
        artifact_id="http://evil.example",
        artifact_type="url",
        verdict="phishing",
        risk_score=0.95,
        category="phishing",
        iocs=("evil.example",),
    )
    assert bus.types() == [
        EventType.ARTIFACT_ANALYZED,
        EventType.IOC_EXTRACTED,
        EventType.RELATIONSHIP_DISCOVERED,
        EventType.THREAT_RECORDED,
    ]
    ioc_event = bus.events[1]
    assert ioc_event.payload["ioc_count"] == 1


def test_ioc_count_without_enumeration() -> None:
    bus = _RecordingBus()
    _publisher(bus).analysis_completed(
        source="file-analysis",
        artifact_id="sha",
        artifact_type="file",
        verdict="benign",
        risk_score=0.0,
        category="none",
        ioc_count=3,
    )
    assert EventType.IOC_EXTRACTED in bus.types()
    assert bus.events[1].payload["ioc_count"] == 3
    # No per-IOC relationships when ids are not enumerated.
    assert EventType.RELATIONSHIP_DISCOVERED not in bus.types()


def test_related_entities_publish_relationships() -> None:
    bus = _RecordingBus()
    _publisher(bus).analysis_completed(
        source="email-analysis",
        artifact_id="msg-1",
        artifact_type="email",
        verdict="benign",
        risk_score=0.0,
        category="none",
        related=(("http://link.example", "url", "contains"),),
    )
    rel = next(e for e in bus.events if e.event_type is EventType.RELATIONSHIP_DISCOVERED)
    assert rel.payload["target_id"] == "http://link.example"
    assert rel.payload["relationship"] == "contains"


def test_incident_campaign_investigation_publish() -> None:
    bus = _RecordingBus()
    pub = _publisher(bus)
    pub.incident_opened(source="s", incident_id="inc-1", title="Wave", artifact_id="a")
    pub.campaign_observed(source="s", campaign_id="camp-1", name="Camp")
    pub.investigation_recorded(source="s", investigation_id="inv-1", artifact_id="a", status="open")
    assert bus.types() == [
        EventType.INCIDENT_CREATED,
        EventType.CAMPAIGN_CREATED,
        EventType.INVESTIGATION_COMPLETED,
    ]


def test_metrics_track_published_and_types() -> None:
    bus = _RecordingBus()
    pub = _publisher(bus)
    pub.analysis_completed(
        source="s",
        artifact_id="a",
        artifact_type="url",
        verdict="phishing",
        risk_score=0.9,
        category="phishing",
        iocs=("x",),
    )
    metrics = pub.metrics()
    assert metrics["events_published"] == 4.0
    assert metrics["publish_failures"] == 0.0
    assert metrics["type.artifact_analyzed"] == 1.0


def test_publish_failure_is_isolated() -> None:
    bus = _ExplodingBus()
    pub = _publisher(bus)
    # Must not raise even though the bus fails on every publish.
    pub.analysis_completed(
        source="s",
        artifact_id="a",
        artifact_type="url",
        verdict="benign",
        risk_score=0.0,
        category="none",
    )
    assert pub.metrics()["publish_failures"] >= 1.0
    assert pub.metrics()["events_published"] == 0.0


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])

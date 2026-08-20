"""Comprehensive tests for the Internal Intelligence Event Bus (M9-P1)."""

from __future__ import annotations

from core.domain.events import (
    EventType,
    IntelligenceEvent,
    artifact_analyzed,
    campaign_created,
    incident_created,
    intelligence_report_generated,
    ioc_extracted,
    provider_completed,
    provider_failed,
    provider_started,
    relationship_discovered,
    threat_matched,
    threat_recorded,
)
from core.interfaces.event_bus import IEventBus
from services.events import EventHistory, InProcessEventBus


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None:
        pass

    def info(self, *a: object, **k: object) -> None:
        pass

    def warning(self, *a: object, **k: object) -> None:
        pass

    def error(self, *a: object, **k: object) -> None:
        pass

    def exception(self, *a: object, **k: object) -> None:
        pass

    def critical(self, *a: object, **k: object) -> None:
        pass

    def bind(self, **k: object) -> _FakeLogger:
        return self


def _bus() -> InProcessEventBus:
    return InProcessEventBus(_FakeLogger())


# --- Event model ---


def test_event_has_stable_fields() -> None:
    event = artifact_analyzed(
        source="file_analysis",
        artifact_id="sha-abc",
        artifact_type="file",
        verdict="phishing",
        risk_score=0.85,
        category="malicious_document",
        correlation_id="inv-1",
    )
    assert event.event_type is EventType.ARTIFACT_ANALYZED
    assert event.source == "file_analysis"
    assert event.artifact_id == "sha-abc"
    assert event.correlation_id == "inv-1"
    assert event.payload["verdict"] == "phishing"
    assert event.event_id  # non-empty
    assert event.timestamp  # non-empty


def test_every_convenience_constructor_produces_event() -> None:
    constructors = [
        lambda: artifact_analyzed(
            source="s",
            artifact_id="a",
            artifact_type="file",
            verdict="v",
            risk_score=0.1,
            category="c",
        ),
        lambda: ioc_extracted(source="s", artifact_id="a", ioc_count=3),
        lambda: threat_matched(source="s", artifact_id="a", threat_id="t"),
        lambda: threat_recorded(source="s", artifact_id="a", artifact_type="file"),
        lambda: incident_created(source="s", incident_id="i", incident_title="t"),
        lambda: campaign_created(source="s", campaign_id="c", campaign_name="n"),
        lambda: provider_started(provider_name="p", version="1", artifact_type="file"),
        lambda: provider_completed(
            provider_name="p", version="1", execution_ms=1.0, evidence_count=2
        ),
        lambda: provider_failed(provider_name="p", version="1", error="boom"),
        lambda: relationship_discovered(
            source="s",
            source_id="a",
            source_type="file",
            target_id="b",
            target_type="url",
            relationship="contains",
        ),
        lambda: intelligence_report_generated(
            source="s", artifact_id="a", verdict="v", severity="high", duration_ms=10.0
        ),
    ]
    for ctor in constructors:
        event = ctor()
        assert isinstance(event, IntelligenceEvent)
        assert event.event_id
        assert event.timestamp


# --- Publication + subscription ---


def test_publish_delivers_to_subscriber() -> None:
    bus = _bus()
    received: list[IntelligenceEvent] = []
    bus.subscribe(EventType.ARTIFACT_ANALYZED, received.append)
    event = artifact_analyzed(
        source="s", artifact_id="a", artifact_type="f", verdict="v", risk_score=0.5, category="c"
    )
    bus.publish(event)
    assert received == [event]


def test_multiple_subscribers_receive_in_order() -> None:
    bus = _bus()
    order: list[int] = []
    bus.subscribe(EventType.IOC_EXTRACTED, lambda _: order.append(1))
    bus.subscribe(EventType.IOC_EXTRACTED, lambda _: order.append(2))
    bus.subscribe(EventType.IOC_EXTRACTED, lambda _: order.append(3))
    bus.publish(ioc_extracted(source="s", artifact_id="a", ioc_count=5))
    assert order == [1, 2, 3]


def test_subscriber_receives_only_matching_type() -> None:
    bus = _bus()
    received: list[IntelligenceEvent] = []
    bus.subscribe(EventType.THREAT_MATCHED, received.append)
    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="a",
            artifact_type="f",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    assert received == []


def test_publish_without_subscribers_succeeds() -> None:
    bus = _bus()
    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="a",
            artifact_type="f",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    assert bus.metrics["total_published"] == 1


# --- Failure isolation ---


def test_failing_handler_does_not_block_others() -> None:
    bus = _bus()
    received: list[int] = []

    def failing(_: IntelligenceEvent) -> None:
        raise RuntimeError("boom")

    bus.subscribe(EventType.THREAT_RECORDED, lambda _: received.append(1))
    bus.subscribe(EventType.THREAT_RECORDED, failing)
    bus.subscribe(EventType.THREAT_RECORDED, lambda _: received.append(3))
    bus.publish(threat_recorded(source="s", artifact_id="a", artifact_type="file"))
    assert received == [1, 3]


def test_failure_increments_metric() -> None:
    bus = _bus()

    def failing(_: IntelligenceEvent) -> None:
        raise ValueError("nope")

    bus.subscribe(EventType.INCIDENT_CREATED, failing)
    bus.publish(incident_created(source="s", incident_id="i", incident_title="t"))
    assert bus.metrics["total_failures"] == 1


# --- Correlation IDs ---


def test_correlation_id_propagates() -> None:
    bus = _bus()
    received: list[IntelligenceEvent] = []
    bus.subscribe(EventType.ARTIFACT_ANALYZED, received.append)
    event = artifact_analyzed(
        source="s",
        artifact_id="a",
        artifact_type="f",
        verdict="v",
        risk_score=0.0,
        category="c",
        correlation_id="chain-42",
    )
    bus.publish(event)
    assert received[0].correlation_id == "chain-42"


# --- Subscriber count ---


def test_subscriber_count() -> None:
    bus = _bus()
    assert bus.subscriber_count() == 0
    bus.subscribe(EventType.IOC_EXTRACTED, lambda _: None)
    bus.subscribe(EventType.IOC_EXTRACTED, lambda _: None)
    bus.subscribe(EventType.THREAT_MATCHED, lambda _: None)
    assert bus.subscriber_count(EventType.IOC_EXTRACTED) == 2
    assert bus.subscriber_count(EventType.THREAT_MATCHED) == 1
    assert bus.subscriber_count() == 3


# --- Metrics / observability ---


def test_metrics_accumulate() -> None:
    bus = _bus()
    bus.subscribe(EventType.ARTIFACT_ANALYZED, lambda _: None)
    bus.subscribe(EventType.ARTIFACT_ANALYZED, lambda _: None)
    for _ in range(3):
        bus.publish(
            artifact_analyzed(
                source="s",
                artifact_id="a",
                artifact_type="f",
                verdict="v",
                risk_score=0.0,
                category="c",
            )
        )
    m = bus.metrics
    assert m["total_published"] == 3
    assert m["total_dispatched"] == 6
    assert m["total_failures"] == 0
    assert float(str(m["total_publish_ms"])) >= 0
    type_counts: dict[str, int] = m["type_counts"]  # type: ignore[assignment]
    assert type_counts["artifact_analyzed"] == 3


# --- Event History ---


def test_event_history_records_events() -> None:
    bus = _bus()
    history = EventHistory(max_size=10)
    history.attach(bus)
    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="a",
            artifact_type="f",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    bus.publish(ioc_extracted(source="s", artifact_id="a", ioc_count=5))
    assert history.count == 2
    assert len(history.recent) == 2
    assert history.recent[0].event_type is EventType.IOC_EXTRACTED  # newest first


def test_event_history_ring_buffer() -> None:
    history = EventHistory(max_size=3)
    for i in range(5):
        history.record(ioc_extracted(source="s", artifact_id=str(i), ioc_count=i))
    assert len(history.recent) == 3
    assert history.count == 5  # lifetime count


def test_event_history_type_statistics() -> None:
    bus = _bus()
    history = EventHistory()
    history.attach(bus)
    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="a",
            artifact_type="f",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="b",
            artifact_type="f",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    bus.publish(ioc_extracted(source="s", artifact_id="a", ioc_count=3))
    stats = history.type_statistics
    assert stats["artifact_analyzed"] == 2
    assert stats["ioc_extracted"] == 1


def test_event_history_recent_by_type() -> None:
    bus = _bus()
    history = EventHistory()
    history.attach(bus)
    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="a",
            artifact_type="f",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    bus.publish(ioc_extracted(source="s", artifact_id="a", ioc_count=3))
    by_type = history.recent_by_type(EventType.ARTIFACT_ANALYZED)
    assert len(by_type) == 1


def test_event_history_summary() -> None:
    history = EventHistory(max_size=100)
    history.record(
        artifact_analyzed(
            source="s",
            artifact_id="a",
            artifact_type="f",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    summary = history.summary()
    assert summary["total_events"] == 1
    assert summary["max_size"] == 100


# --- Interface conformance ---


def test_bus_satisfies_ieventbus() -> None:
    bus = _bus()
    assert isinstance(bus, IEventBus)


# --- Provider events ---


def test_provider_events_carry_metadata() -> None:
    started = provider_started(
        provider_name="YARA", version="4.0", artifact_type="file", artifact_id="sha-abc"
    )
    assert started.payload["version"] == "4.0"
    assert started.payload["artifact_type"] == "file"

    completed = provider_completed(
        provider_name="YARA", version="4.0", execution_ms=42.5, evidence_count=3
    )
    assert completed.payload["execution_ms"] == 42.5

    failed = provider_failed(provider_name="YARA", version="4.0", error="timeout")
    assert failed.payload["error"] == "timeout"


# --- Regression: existing services unaffected ---


def test_file_analysis_service_still_works() -> None:
    """The event bus is additive — existing services don't depend on it."""
    from ai.file_analysis import EntropyProvider, HybridFileAnalyzer, StructureProvider
    from core.domain.intelligence import EvidenceSource
    from services.file_analysis.ingestion import FileIngestor

    analyzer = HybridFileAnalyzer(
        [StructureProvider(), EntropyProvider()],
        weights={EvidenceSource.FILE_STRUCTURE: 1.0},
        suspicious_threshold=0.35,
        phishing_threshold=0.65,
    )
    artifact = FileIngestor().ingest("test.txt", b"safe content")
    report = analyzer.analyze(artifact)
    assert report.verdict.value == "legitimate"

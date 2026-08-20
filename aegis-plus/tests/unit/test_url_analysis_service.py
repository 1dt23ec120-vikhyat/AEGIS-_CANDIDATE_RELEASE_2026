"""Tests for the URL analysis service (orchestration + threat protection)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from core.constants import ArtifactType, AuditOutcome, BlockSource
from core.domain import Evidence, EvidenceSource, ThreatCategory, Url, UrlAnalysis, Verdict
from core.domain.analysis import FeatureContribution
from core.domain.intelligence import IntelligenceReport
from core.entities import ThreatEntry, UrlScan
from core.exceptions import ValidationError
from core.interfaces import (
    IDomainIntelligenceProvider,
    IReputationProvider,
    IThreatProtectionService,
    IUrlAnalyzer,
)
from infrastructure.logging import get_logger
from services.url_analysis import UrlAnalysisService

pytestmark = pytest.mark.unit


def _analysis(verdict: Verdict) -> UrlAnalysis:
    return UrlAnalysis(
        verdict=verdict,
        threat_score=0.8 if verdict is Verdict.PHISHING else 0.2,
        confidence=0.9,
        features={"url_length": 20},
        contributions=(FeatureContribution("x", "detail", 0.3, True),),
    )


class _FakeAnalyzer(IUrlAnalyzer):
    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        self.called = 0

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.ML

    def analyze(self, url: Url) -> UrlAnalysis:
        self.called += 1
        return _analysis(self.verdict)


class _FakeDomain(IDomainIntelligenceProvider):
    def assess(self, url: Url) -> Evidence:
        return Evidence(
            source=EvidenceSource.DOMAIN,
            risk=0.0,
            confidence=0.7,
            weight=1.0,
            rationale="test domain",
            category=ThreatCategory.NONE,
        )


class _FakeReputation(IReputationProvider):
    @property
    def name(self) -> str:
        return "none"

    @property
    def enabled(self) -> bool:
        return False

    def check(self, url: Url) -> Evidence:
        return Evidence(
            source=EvidenceSource.REPUTATION,
            risk=0.0,
            confidence=0.0,
            weight=1.0,
            rationale="disabled",
            available=False,
        )


class _FakeThreat(IThreatProtectionService):
    def __init__(self, existing: ThreatEntry | None = None) -> None:
        self.existing = existing
        self.recorded: list[str] = []
        self.hits: list[str] = []

    def lookup(self, url: Url) -> ThreatEntry | None:
        return self.existing

    def record_detection(
        self, url: Url, analysis: UrlAnalysis, *, source: BlockSource = BlockSource.AI
    ) -> ThreatEntry:
        self.recorded.append(str(url))
        return ThreatEntry.from_analysis(url, analysis, source=source)

    def record_report(
        self,
        artifact_hash: str,
        artifact: str,
        report: IntelligenceReport,
        *,
        artifact_type: ArtifactType,
        source: BlockSource = BlockSource.AI,
    ) -> ThreatEntry:
        self.recorded.append(artifact)
        return ThreatEntry.from_report(
            artifact_hash, artifact, report, artifact_type=artifact_type, source=source
        )

    def register_hit(self, entry: ThreatEntry) -> ThreatEntry:
        self.hits.append(entry.artifact)
        return entry


class _FakeRepo:
    def __init__(self, store: list[UrlScan]) -> None:
        self._store = store

    def add(self, entity: UrlScan) -> UrlScan:
        self._store.append(entity)
        return entity

    def list(self) -> list[UrlScan]:
        return list(self._store)


class _FakeUoW:
    def __init__(self, store: list[UrlScan]) -> None:
        self._repo = _FakeRepo(store)

    def __enter__(self) -> _FakeUoW:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get_repository(self, entity_type: type[Any]) -> _FakeRepo:
        return self._repo

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass


class _FakeAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def record(self, action: str, *, outcome: AuditOutcome, **_: object) -> None:
        self.events.append((action, outcome.value))

    def success(self, action: str, **_: object) -> None:
        self.events.append((action, "success"))

    def failure(self, action: str, **_: object) -> None:
        self.events.append((action, "failure"))


_WEIGHTS = {
    EvidenceSource.ML: 1.0,
    EvidenceSource.HEURISTIC: 0.8,
    EvidenceSource.REPUTATION: 1.2,
    EvidenceSource.THREAT_INTEL: 1.5,
    EvidenceSource.DOMAIN: 0.9,
}


def _service(
    analyzer: _FakeAnalyzer, threat: _FakeThreat, store: list[UrlScan], audit: _FakeAudit
) -> UrlAnalysisService:
    return UrlAnalysisService(
        [analyzer],
        _FakeDomain(),
        _FakeReputation(),
        threat,
        lambda: _FakeUoW(store),  # type: ignore[arg-type,return-value]
        audit,  # type: ignore[arg-type]
        get_logger("test"),
        weights=_WEIGHTS,
        suspicious_threshold=0.35,
        phishing_threshold=0.70,
    )


def test_benign_is_not_blacklisted() -> None:
    analyzer = _FakeAnalyzer(Verdict.SUSPICIOUS)
    threat = _FakeThreat()
    outcome = _service(analyzer, threat, [], _FakeAudit()).analyze("https://example.com")
    assert outcome.blacklisted is False
    assert threat.recorded == []


def test_phishing_is_auto_blacklisted() -> None:
    analyzer = _FakeAnalyzer(Verdict.PHISHING)
    threat = _FakeThreat()
    store: list[UrlScan] = []
    outcome = _service(analyzer, threat, store, _FakeAudit()).analyze("http://bad.example")
    assert outcome.blacklisted is True
    assert outcome.blacklist_hit is False
    assert len(threat.recorded) == 1
    assert len(store) == 1


def test_blacklisted_url_skips_analysis() -> None:
    url = Url.create("http://known-bad.example/login")
    entry = ThreatEntry.from_analysis(url, _analysis(Verdict.PHISHING))
    analyzer = _FakeAnalyzer(Verdict.LEGITIMATE)
    threat = _FakeThreat(existing=entry)
    store: list[UrlScan] = []

    outcome = _service(analyzer, threat, store, _FakeAudit()).analyze(str(url))

    assert outcome.blacklist_hit is True
    assert outcome.blacklisted is True
    assert analyzer.called == 0  # pipeline skipped
    assert threat.hits == [entry.artifact]
    assert store == []  # no new scan persisted on a hit


def test_invalid_url_raises() -> None:
    with pytest.raises(ValidationError):
        _service(_FakeAnalyzer(Verdict.LEGITIMATE), _FakeThreat(), [], _FakeAudit()).analyze(
            "ftp://x"
        )


def test_threat_entry_registers_repeat_detection() -> None:
    url = Url.create("http://bad.example")
    entry = ThreatEntry.from_analysis(url, _analysis(Verdict.PHISHING))
    assert entry.detection_count == 1
    before = entry.last_detected
    entry.first_detected = datetime(2020, 1, 1, tzinfo=UTC)
    entry.register_detection()
    assert entry.detection_count == 2
    assert entry.last_detected >= before

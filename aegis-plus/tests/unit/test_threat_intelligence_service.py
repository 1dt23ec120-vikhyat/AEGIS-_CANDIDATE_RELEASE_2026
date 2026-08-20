"""Tests for the ThreatIntelligenceService (with fakes)."""

from __future__ import annotations

from typing import Any

import pytest

from core.constants import AuditOutcome
from core.domain import Url, Verdict
from core.domain.analysis import FeatureContribution, UrlAnalysis
from core.entities import ThreatEntry
from infrastructure.logging import get_logger
from services.threat_intelligence import ThreatIntelligenceService

pytestmark = pytest.mark.unit


def _analysis() -> UrlAnalysis:
    return UrlAnalysis(
        verdict=Verdict.PHISHING,
        threat_score=0.8,
        confidence=0.6,
        features={},
        contributions=(FeatureContribution("x", "d", 0.3, True),),
    )


class _FakeThreatRepo:
    def __init__(self, store: dict[str, ThreatEntry]) -> None:
        self._store = store

    def find_by_hash(self, artifact_hash: str) -> ThreatEntry | None:
        return self._store.get(artifact_hash)

    def add(self, entity: ThreatEntry) -> ThreatEntry:
        self._store[entity.artifact_hash] = entity
        return entity

    def update(self, entity: ThreatEntry) -> ThreatEntry:
        self._store[entity.artifact_hash] = entity
        return entity

    def list_recent(self) -> list[ThreatEntry]:
        return sorted(self._store.values(), key=lambda e: e.last_detected, reverse=True)


class _FakeUoW:
    def __init__(self, store: dict[str, ThreatEntry]) -> None:
        self._repo = _FakeThreatRepo(store)

    def __enter__(self) -> _FakeUoW:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get_repository(self, entity_type: type[Any]) -> _FakeThreatRepo:
        return self._repo

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass


class _FakeAudit:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def record(self, action: str, *, outcome: AuditOutcome, **_: object) -> None:
        self.actions.append(action)

    def success(self, action: str, **_: object) -> None:
        self.actions.append(action)

    def failure(self, action: str, **_: object) -> None:
        self.actions.append(action)


def _service(store: dict[str, ThreatEntry], audit: _FakeAudit) -> ThreatIntelligenceService:
    return ThreatIntelligenceService(
        lambda: _FakeUoW(store),  # type: ignore[arg-type,return-value]
        audit,  # type: ignore[arg-type]
        get_logger("test"),
    )


def test_record_detection_adds_then_updates() -> None:
    store: dict[str, ThreatEntry] = {}
    audit = _FakeAudit()
    svc = _service(store, audit)
    url = Url.create("http://bad.example/login")

    first = svc.record_detection(url, _analysis())
    assert first.detection_count == 1
    assert len(store) == 1

    second = svc.record_detection(url, _analysis())
    assert second.detection_count == 2
    assert len(store) == 1  # same entry updated
    assert "threat.blacklisted" in audit.actions


def test_lookup_and_is_blocked() -> None:
    store: dict[str, ThreatEntry] = {}
    svc = _service(store, _FakeAudit())
    url = Url.create("http://bad.example")
    assert svc.lookup(url) is None
    svc.record_detection(url, _analysis())
    assert svc.is_blocked(url) is True


def test_guard_open_audits_when_blocked() -> None:
    store: dict[str, ThreatEntry] = {}
    audit = _FakeAudit()
    svc = _service(store, audit)
    url = Url.create("http://bad.example")
    svc.record_detection(url, _analysis())

    blocked = svc.guard_open(url)
    assert blocked is not None
    assert "threat.open_blocked" in audit.actions

    safe = svc.guard_open(Url.create("https://good.example"))
    assert safe is None


def test_stats_and_list() -> None:
    store: dict[str, ThreatEntry] = {}
    svc = _service(store, _FakeAudit())
    svc.record_detection(Url.create("http://a.example"), _analysis())
    svc.record_detection(Url.create("http://b.example"), _analysis())

    stats = svc.stats()
    assert stats.total_blacklisted == 2
    assert stats.high_risk_count == 2  # both risk 0.8 >= 0.70
    assert stats.most_recent is not None
    assert len(svc.list_threats()) == 2

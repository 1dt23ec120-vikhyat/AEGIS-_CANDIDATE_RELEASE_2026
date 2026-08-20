"""Tests for the email analysis service orchestration."""

from __future__ import annotations

from types import TracebackType
from typing import Any

from core.constants import ArtifactType, BlockSource
from core.domain import Verdict
from core.domain.analysis import FeatureContribution
from core.domain.email import EmailMessage
from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    IntelligenceReport,
    SourceScore,
    ThreatCategory,
    combine_evidence,
)
from core.domain.url import Url
from core.domain.value_objects import EntityId
from core.entities import EmailScan, ThreatEntry, UrlScan
from core.interfaces import (
    IAuditTrail,
    IEmailAnalyzer,
    IRepository,
    IThreatProtectionService,
    IUnitOfWork,
)
from infrastructure.logging import get_logger
from services.email_analysis import EmailAnalysisService
from services.url_analysis.service import ScanOutcome, UrlAnalysisService

_SAFE = "From: friend@example.com\nSubject: lunch\n\nWant to grab lunch tomorrow?\n"
_PHISH = (
    "From: PayPal <no-reply@paypal-secure.xyz>\n"
    "Authentication-Results: mx; spf=fail dkim=fail dmarc=fail\n"
    "Subject: Urgent: verify your account\n\n"
    "Your account is suspended. Click here to verify and reset your password.\n"
)


class _FakeAnalyzer(IEmailAnalyzer):
    def __init__(self, verdict: Verdict) -> None:
        self._verdict = verdict

    def analyze(
        self, email: EmailMessage, *, extra_evidence: tuple[Evidence, ...] = ()
    ) -> IntelligenceReport:
        risk = 0.9 if self._verdict is Verdict.PHISHING else 0.0
        evidence = Evidence(
            source=EvidenceSource.LANGUAGE,
            risk=risk,
            confidence=0.8,
            weight=1.0,
            rationale="test",
            category=ThreatCategory.PHISHING if risk else ThreatCategory.NONE,
            contributions=(FeatureContribution("credential_request", "verify", 0.5, risk > 0),),
            available=True,
        )
        return combine_evidence(
            (evidence, *extra_evidence),
            suspicious_threshold=0.35,
            phishing_threshold=0.65,
        )


class _UnusedUrlService(UrlAnalysisService):
    def __init__(self) -> None:
        pass

    def analyze(self, raw_url: str, *, actor: str | None = None) -> ScanOutcome:
        scan = UrlScan(
            url=raw_url,
            verdict=Verdict.LEGITIMATE,
            threat_score=0.0,
            confidence=0.5,
            contributions=(),
            features={},
        )
        return ScanOutcome(scan=scan, blacklisted=False, blacklist_hit=False)


class _FakeThreat(IThreatProtectionService):
    def __init__(self) -> None:
        self.reports: list[tuple[str, ArtifactType]] = []

    def lookup(self, url: Url) -> ThreatEntry | None:
        return None

    def record_detection(
        self, url: Url, analysis: Any, *, source: BlockSource = BlockSource.AI
    ) -> ThreatEntry:  # pragma: no cover - unused here
        raise NotImplementedError

    def record_report(
        self,
        artifact_hash: str,
        artifact: str,
        report: IntelligenceReport,
        *,
        artifact_type: ArtifactType,
        source: BlockSource = BlockSource.AI,
    ) -> ThreatEntry:
        self.reports.append((artifact, artifact_type))
        return ThreatEntry.from_report(artifact_hash, artifact, report, artifact_type=artifact_type)

    def register_hit(self, entry: ThreatEntry) -> ThreatEntry:  # pragma: no cover
        return entry


class _FakeRepo(IRepository[EmailScan]):
    def __init__(self, store: list[EmailScan]) -> None:
        self._store = store

    def add(self, entity: EmailScan) -> EmailScan:
        self._store.append(entity)
        return entity

    def get(self, entity_id: EntityId) -> EmailScan | None:  # pragma: no cover
        return None

    def list(self) -> list[EmailScan]:
        return list(self._store)

    def update(self, entity: EmailScan) -> EmailScan:  # pragma: no cover
        return entity

    def delete(self, entity_id: EntityId) -> None:  # pragma: no cover
        return None


class _FakeUow(IUnitOfWork):
    def __init__(self, store: list[EmailScan]) -> None:
        self._repo: _FakeRepo = _FakeRepo(store)
        self.committed = False

    def __enter__(self) -> IUnitOfWork:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:  # pragma: no cover
        return None

    def get_repository(self, entity_type: type[Any]) -> Any:
        return self._repo


class _FakeAudit(IAuditTrail):
    def __init__(self) -> None:
        self.events: list[str] = []

    def record(self, action: str, **context: Any) -> None:
        self.events.append(action)

    def success(self, action: str, **context: Any) -> None:
        self.events.append(action)

    def failure(self, action: str, **context: Any) -> None:
        self.events.append(f"{action}:fail")


def _service(verdict: Verdict, threat: _FakeThreat, store: list[EmailScan]) -> EmailAnalysisService:
    return EmailAnalysisService(
        _FakeAnalyzer(verdict),
        _UnusedUrlService(),
        threat,
        lambda: _FakeUow(store),
        _FakeAudit(),
        get_logger("test-email"),
    )


def test_safe_email_is_persisted_but_not_blacklisted() -> None:
    store: list[EmailScan] = []
    threat = _FakeThreat()
    outcome = _service(Verdict.LEGITIMATE, threat, store).analyze(_SAFE)
    assert not outcome.malicious
    assert len(store) == 1
    assert threat.reports == []


def test_malicious_email_is_recorded_as_email_artifact() -> None:
    store: list[EmailScan] = []
    threat = _FakeThreat()
    outcome = _service(Verdict.PHISHING, threat, store).analyze(_PHISH)
    assert outcome.malicious
    assert len(store) == 1
    assert len(threat.reports) == 1
    assert threat.reports[0][1] is ArtifactType.EMAIL


def test_source_scores_include_the_url_source() -> None:
    store: list[EmailScan] = []
    outcome = _service(Verdict.LEGITIMATE, _FakeThreat(), store).analyze(_SAFE)
    sources = {s.source for s in outcome.scan.sources}
    assert EvidenceSource.URL in sources
    assert all(isinstance(s, SourceScore) for s in outcome.scan.sources)

"""Email analysis service.

Orchestrates the Email Analysis use case, maximizing reuse of the existing
platform. It parses the message, extracts embedded URLs and runs each through the
**existing URL Intelligence Engine** (`UrlAnalysisService` - reusing its ML,
hybrid detection, threat intelligence, auto-protection, and persistence), folds
the worst URL result in as one evidence source, and hands the message to the
hybrid email analyzer. The combined report is persisted as an `EmailScan`,
audited, and - when malicious - recorded in the shared Threat Intelligence store
as an ``EMAIL`` artifact.

The service depends only on Core ports and the URL application service; it never
duplicates URL logic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from core.constants import ArtifactType
from core.domain import Verdict
from core.domain.email import EmailMessage
from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    FeatureContribution,
    ThreatCategory,
)
from core.domain.value_objects import EntityId
from core.entities import EmailScan
from core.exceptions import ValidationError
from core.interfaces import (
    IAuditTrail,
    IEmailAnalyzer,
    ILogger,
    IThreatProtectionService,
    IUnitOfWork,
)
from services.incident import IncidentCorrelationService
from services.pipeline import IntelligencePublisher
from services.url_analysis.service import UrlAnalysisService

_ACTION = "email.analyze"
_MALICIOUS_VERDICTS = frozenset({Verdict.PHISHING})


@dataclass(frozen=True, slots=True)
class EmbeddedUrlResult:
    """The result of analyzing one URL embedded in an email."""

    url: str
    verdict: str
    risk_percent: int
    blacklisted: bool


@dataclass(frozen=True, slots=True)
class EmailScanOutcome:
    """The result of an email analysis request."""

    scan: EmailScan
    malicious: bool
    urls: tuple[EmbeddedUrlResult, ...]
    email: EmailMessage | None = None
    prior_sender_scans: int = 0
    prior_sender_malicious: int = 0
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    correlation_rationale: str = ""


class EmailAnalysisService:
    """Application service for the Email Analysis vertical."""

    def __init__(
        self,
        email_analyzer: IEmailAnalyzer,
        url_service: UrlAnalysisService,
        threat_protection: IThreatProtectionService,
        unit_of_work_factory: Callable[[], IUnitOfWork],
        audit: IAuditTrail,
        logger: ILogger,
        correlation: IncidentCorrelationService | None = None,
        publisher: IntelligencePublisher | None = None,
    ) -> None:
        """Initialize the service.

        Args:
            email_analyzer: The hybrid email analyzer.
            url_service: The existing URL analysis service (reused per URL).
            threat_protection: The shared threat protection port.
            unit_of_work_factory: Produces a Unit of Work for persistence.
            audit: The audit trail port.
            logger: Injected logger.
            correlation: Optional incident correlation service; when provided,
                malicious detections are correlated into incidents and campaigns.
            publisher: Optional live-pipeline publisher; when provided, analysis
                results are published as intelligence events onto the event bus.
        """
        self._analyzer = email_analyzer
        self._url_service = url_service
        self._threat = threat_protection
        self._unit_of_work_factory = unit_of_work_factory
        self._audit = audit
        self._logger = logger
        self._correlation = correlation
        self._publisher = publisher

    def analyze(self, raw_email: str, *, actor: str | None = None) -> EmailScanOutcome:
        """Analyze a raw email message end-to-end.

        Args:
            raw_email: The raw RFC-822 message.
            actor: Identifier of the requester, if known.

        Returns:
            The :class:`EmailScanOutcome`.

        Raises:
            ValidationError: If the message cannot be parsed.
        """
        try:
            email = EmailMessage.parse(raw_email)
        except ValidationError:
            self._audit.failure(_ACTION, resource="email", reason="invalid_email")
            raise

        url_results, url_evidence, malicious_urls = self._analyze_embedded_urls(email)
        report = self._analyzer.analyze(
            email, extra_evidence=(url_evidence, self._clean_threat_evidence())
        )
        scan = EmailScan.from_report(
            email,
            report,
            url_count=len(email.urls),
            malicious_url_count=malicious_urls,
            actor=actor,
        )

        with self._unit_of_work_factory() as uow:
            repo = uow.get_repository(EmailScan)
            prior = [s for s in repo.list() if s.sender == email.sender.address]
            prior_malicious = sum(1 for s in prior if s.verdict is Verdict.PHISHING)
            repo.add(scan)
            uow.commit()

        self._logger.info(
            "Email analyzed: {} -> {} ({}%), {} URL(s), {} malicious",
            email.sender.address,
            report.verdict.value,
            report.risk_percent,
            len(email.urls),
            malicious_urls,
        )
        self._audit.success(
            _ACTION,
            resource=email.identity,
            verdict=report.verdict.value,
            category=report.primary_category.value,
            threat_score=report.risk_score,
        )

        malicious = report.verdict in _MALICIOUS_VERDICTS
        incident_id = ""
        incident_title = ""
        campaign_id = ""
        campaign_name = ""
        rationale = ""
        if malicious:
            self._threat.record_report(
                email.fingerprint,
                email.identity,
                report,
                artifact_type=ArtifactType.EMAIL,
            )
            if self._correlation is not None:
                correlated = self._correlation.correlate_email(
                    email, scan, tuple(r.url for r in url_results)
                )
                incident_id = str(correlated.incident.id)
                incident_title = correlated.incident.title
                campaign_id = str(correlated.campaign.id)
                campaign_name = correlated.campaign.name
                rationale = (
                    "New incident opened"
                    if correlated.created_incident
                    else correlated.link.rationale
                )

        self._publish_email(
            email,
            url_results,
            verdict=report.verdict.value,
            risk_score=report.risk_score,
            category=report.primary_category.value,
            malicious=malicious,
            incident_id=incident_id,
            incident_title=incident_title,
            campaign_id=campaign_id,
            campaign_name=campaign_name,
        )
        return EmailScanOutcome(
            scan=scan,
            malicious=malicious,
            urls=url_results,
            email=email,
            prior_sender_scans=len(prior),
            prior_sender_malicious=prior_malicious,
            incident_id=incident_id,
            incident_title=incident_title,
            campaign_name=campaign_name,
            correlation_rationale=rationale,
        )

    def _publish_email(
        self,
        email: EmailMessage,
        url_results: tuple[EmbeddedUrlResult, ...],
        *,
        verdict: str,
        risk_score: float,
        category: str,
        malicious: bool,
        incident_id: str,
        incident_title: str,
        campaign_id: str,
        campaign_name: str,
    ) -> None:
        """Publish analysis events for an email (no-op without a publisher)."""
        if self._publisher is None:
            return
        sender_domain = email.sender.address.rsplit("@", 1)[-1]
        self._publisher.analysis_completed(
            source="email-analysis",
            artifact_id=email.identity,
            artifact_type="email",
            verdict=verdict,
            risk_score=risk_score,
            category=category,
            iocs=(sender_domain,),
            related=tuple((r.url, "url", "contains") for r in url_results),
            malicious=malicious,
        )
        if incident_id:
            self._publisher.incident_opened(
                source="email-analysis",
                incident_id=incident_id,
                title=incident_title,
                artifact_id=email.identity,
            )
        if campaign_id:
            self._publisher.campaign_observed(
                source="email-analysis", campaign_id=campaign_id, name=campaign_name
            )

    def get_scan(self, scan_id: str) -> EmailScan | None:
        """Return a persisted email scan by id, or ``None`` if absent.

        A read-only lookup over the existing scan repository. Reused by the Gmail
        connector's workspace read-model to surface the *existing* analysis for a
        message without re-analyzing it. Never recomputes intelligence.
        """
        try:
            entity_id = EntityId.from_string(scan_id)
        except ValidationError:
            return None
        with self._unit_of_work_factory() as uow:
            return uow.get_repository(EmailScan).get(entity_id)

    def recent(self, limit: int = 10) -> list[EmailScan]:
        """Return the most recent email scans, newest first."""
        with self._unit_of_work_factory() as uow:
            scans = uow.get_repository(EmailScan).list()
        scans.sort(key=lambda scan: scan.created_at, reverse=True)
        return scans[:limit]

    def _analyze_embedded_urls(
        self, email: EmailMessage
    ) -> tuple[tuple[EmbeddedUrlResult, ...], Evidence, int]:
        """Run each embedded URL through the existing URL engine (reuse)."""
        results: list[EmbeddedUrlResult] = []
        worst = 0.0
        malicious = 0
        for raw_url in email.urls:
            outcome = self._url_service.analyze(raw_url)
            scan = outcome.scan
            results.append(
                EmbeddedUrlResult(
                    url=scan.url,
                    verdict=scan.verdict.value,
                    risk_percent=round(scan.threat_score * 100),
                    blacklisted=outcome.blacklisted,
                )
            )
            worst = max(worst, scan.threat_score)
            if scan.verdict in _MALICIOUS_VERDICTS:
                malicious += 1

        contributions = tuple(
            FeatureContribution(
                feature="malicious_embedded_url",
                detail=f"Embedded URL flagged: {r.url}",
                weight=0.6,
                triggered=True,
            )
            for r in results
            if r.verdict == Verdict.PHISHING.value
        )
        evidence = Evidence(
            source=EvidenceSource.URL,
            risk=round(worst, 4),
            confidence=0.9 if email.urls else 0.0,
            weight=1.0,
            rationale=f"{len(email.urls)} embedded URL(s) analyzed by the URL engine",
            category=ThreatCategory.PHISHING if malicious else ThreatCategory.NONE,
            contributions=contributions,
            available=bool(email.urls),
        )
        return tuple(results), evidence, malicious

    @staticmethod
    def _clean_threat_evidence() -> Evidence:
        return Evidence(
            source=EvidenceSource.THREAT_INTEL,
            risk=0.0,
            confidence=0.9,
            weight=1.0,
            rationale="No prior detections in threat intelligence",
            category=ThreatCategory.NONE,
            available=True,
        )

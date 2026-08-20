"""File Analysis application service.

Orchestrates the File Intelligence vertical end-to-end, mirroring the URL and
email services: ingest raw bytes into a byte-free artifact, reuse the URL engine
for every embedded URL, combine evidence into a report, persist a byte-free
:class:`FileScan`, and - for malicious files - record the file in Threat
Intelligence and correlate it into incidents and campaigns.

Reuse over duplication: embedded URLs go through the existing
:class:`UrlAnalysisService`, blacklisting goes through the shared
:class:`ThreatIntelligenceService` recording path, and correlation goes through
:class:`IncidentCorrelationService`. Raw bytes exist only for the duration of
:meth:`analyze` and are never persisted.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from core.constants import ArtifactType
from core.domain.analysis import Verdict
from core.domain.correlation import ArtifactKind, ArtifactRef
from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    FeatureContribution,
    IntelligenceReport,
    ThreatCategory,
)
from core.domain.ioc import IocCollection
from core.entities import FileScan
from core.exceptions import ValidationError
from core.interfaces import (
    AnalyzedArtifact,
    IAuditTrail,
    IFileAnalyzer,
    ILogger,
    IThreatProtectionService,
    IUnitOfWork,
)
from services.file_analysis.ingestion import FileIngestor
from services.incident import IncidentCorrelationService
from services.pipeline import IntelligencePublisher
from services.url_analysis.service import UrlAnalysisService

_ACTION = "file.analyze"
_MALICIOUS_VERDICTS = frozenset({Verdict.PHISHING})


@dataclass(frozen=True, slots=True)
class EmbeddedUrlResult:
    """The result of analyzing one URL embedded in a file."""

    url: str
    verdict: str
    risk_percent: int
    blacklisted: bool


@dataclass(frozen=True, slots=True)
class FileScanOutcome:
    """The result of a file analysis request."""

    scan: FileScan
    malicious: bool
    artifact: AnalyzedArtifact
    urls: tuple[EmbeddedUrlResult, ...] = ()
    indicators: IocCollection = field(default_factory=IocCollection)
    incident_id: str = ""
    incident_title: str = ""
    campaign_name: str = ""
    correlation_rationale: str = ""


class FileAnalysisService:
    """Application service for the File Analysis vertical."""

    def __init__(
        self,
        file_analyzer: IFileAnalyzer,
        url_service: UrlAnalysisService,
        threat_protection: IThreatProtectionService,
        unit_of_work_factory: Callable[[], IUnitOfWork],
        audit: IAuditTrail,
        logger: ILogger,
        *,
        ingestor: FileIngestor | None = None,
        correlation: IncidentCorrelationService | None = None,
        publisher: IntelligencePublisher | None = None,
    ) -> None:
        """Initialize the service.

        Args:
            file_analyzer: The hybrid file analyzer.
            url_service: The existing URL analysis service (reused per URL).
            threat_protection: The shared threat protection port.
            unit_of_work_factory: Produces a Unit of Work for persistence.
            audit: The audit trail port.
            logger: Injected logger.
            ingestor: Optional custom ingestor (size bounds); defaults applied.
            correlation: Optional incident correlation service; when provided,
                malicious files are correlated into incidents and campaigns.
            publisher: Optional live-pipeline publisher; when provided, analysis
                results are published as intelligence events onto the event bus.
        """
        self._analyzer = file_analyzer
        self._url_service = url_service
        self._threat = threat_protection
        self._unit_of_work_factory = unit_of_work_factory
        self._audit = audit
        self._logger = logger
        self._ingestor = ingestor or FileIngestor()
        self._correlation = correlation
        self._publisher = publisher

    def analyze(self, filename: str, data: bytes, *, actor: str | None = None) -> FileScanOutcome:
        """Analyze a file end-to-end.

        Args:
            filename: The client-supplied filename.
            data: The raw file bytes (not retained after analysis).
            actor: Identifier of the requester, if known.

        Returns:
            The :class:`FileScanOutcome`.

        Raises:
            ValidationError: If the file is empty or exceeds the size limit.
        """
        try:
            artifact = self._ingestor.ingest(filename, data)
        except ValidationError:
            self._audit.failure(_ACTION, resource=filename, reason="invalid_file")
            raise

        url_results, url_evidence, malicious_urls = self._analyze_embedded_urls(artifact)
        report = self._analyzer.analyze(
            artifact, extra_evidence=(url_evidence, self._clean_threat_evidence())
        )
        scan = FileScan.from_report(
            filename=artifact.filename,
            size=artifact.size,
            fingerprints=artifact.fingerprints,
            file_kind=artifact.file_type.kind.value,
            detected_mime=artifact.file_type.detected_mime,
            entropy=artifact.entropy.entropy,
            report=report,
            indicator_count=artifact.indicators.total,
            url_count=len(artifact.indicators.urls),
            malicious_url_count=malicious_urls,
            actor=actor,
        )

        with self._unit_of_work_factory() as uow:
            uow.get_repository(FileScan).add(scan)
            uow.commit()

        self._logger.info(
            "File analyzed: {} ({}) -> {} ({}%), {} indicator(s), {} malicious URL(s)",
            artifact.filename,
            artifact.fingerprints.sha256[:16],
            report.verdict.value,
            report.risk_percent,
            artifact.indicators.total,
            malicious_urls,
        )
        self._audit.success(
            _ACTION,
            resource=artifact.fingerprints.sha256,
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
                artifact.fingerprints.sha256,
                artifact.filename,
                report,
                artifact_type=ArtifactType.FILE,
            )
            if self._correlation is not None:
                correlated = self._correlation.correlate_file(
                    artifacts=self._correlation_artifacts(artifact, report),
                    category=report.primary_category,
                    risk_score=report.risk_score,
                    scan_id=str(scan.id),
                    filename=artifact.filename,
                    verdict=report.verdict.value,
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

        self._publish_file(
            artifact,
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
        return FileScanOutcome(
            scan=scan,
            malicious=malicious,
            artifact=artifact,
            urls=url_results,
            indicators=artifact.indicators,
            incident_id=incident_id,
            incident_title=incident_title,
            campaign_name=campaign_name,
            correlation_rationale=rationale,
        )

    def _publish_file(
        self,
        artifact: AnalyzedArtifact,
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
        """Publish analysis events for a file (no-op without a publisher)."""
        if self._publisher is None:
            return
        self._publisher.analysis_completed(
            source="file-analysis",
            artifact_id=artifact.fingerprints.sha256,
            artifact_type="file",
            verdict=verdict,
            risk_score=risk_score,
            category=category,
            ioc_count=artifact.indicators.total,
            related=tuple((r.url, "url", "contains") for r in url_results),
            malicious=malicious,
        )
        if incident_id:
            self._publisher.incident_opened(
                source="file-analysis",
                incident_id=incident_id,
                title=incident_title,
                artifact_id=artifact.fingerprints.sha256,
            )
        if campaign_id:
            self._publisher.campaign_observed(
                source="file-analysis", campaign_id=campaign_id, name=campaign_name
            )

    def recent(self, limit: int = 10) -> list[FileScan]:
        """Return the most recent file scans, newest first."""
        with self._unit_of_work_factory() as uow:
            scans = uow.get_repository(FileScan).list()
        scans.sort(key=lambda scan: scan.created_at, reverse=True)
        return scans[:limit]

    # --- helpers --------------------------------------------------------

    def _analyze_embedded_urls(
        self, artifact: AnalyzedArtifact
    ) -> tuple[tuple[EmbeddedUrlResult, ...], Evidence, int]:
        """Run each embedded URL through the existing URL engine (reuse)."""
        results: list[EmbeddedUrlResult] = []
        worst = 0.0
        malicious = 0
        for raw_url in artifact.indicators.urls:
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
                detail=f"Embedded URL flagged: {result.url}",
                weight=0.6,
                triggered=True,
            )
            for result in results
            if result.verdict == Verdict.PHISHING.value
        )
        has_urls = bool(artifact.indicators.urls)
        evidence = Evidence(
            source=EvidenceSource.URL,
            risk=round(worst, 4),
            confidence=0.9 if has_urls else 0.0,
            weight=1.0,
            rationale=f"{len(artifact.indicators.urls)} embedded URL(s) analyzed by the URL engine",
            category=ThreatCategory.PHISHING if malicious else ThreatCategory.NONE,
            contributions=contributions,
            available=has_urls,
        )
        return tuple(results), evidence, malicious

    @staticmethod
    def _correlation_artifacts(
        artifact: AnalyzedArtifact, report: IntelligenceReport
    ) -> tuple[ArtifactRef, ...]:
        """Extract correlatable observables from a file detection."""
        refs: list[ArtifactRef] = [
            ArtifactRef(ArtifactKind.FILE_HASH, artifact.fingerprints.sha256),
            ArtifactRef(ArtifactKind.FILE_NAME, artifact.filename),
        ]
        for url in artifact.indicators.urls:
            refs.append(ArtifactRef(ArtifactKind.URL, url))
            digest = hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()
            refs.append(ArtifactRef(ArtifactKind.URL_HASH, digest))
        for domain in artifact.indicators.domains:
            refs.append(ArtifactRef(ArtifactKind.DOMAIN, domain))
        if report.primary_category is not ThreatCategory.NONE:
            refs.append(ArtifactRef(ArtifactKind.CATEGORY, report.primary_category.value))
        return tuple({ref.key: ref for ref in refs}.values())

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

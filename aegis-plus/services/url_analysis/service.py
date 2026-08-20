"""URL analysis service (hybrid intelligence engine).

Orchestrates the URL Intelligence use case. It consults the blacklist first
(short-circuiting the pipeline on a hit), then gathers evidence from every
available source - each analyzer (ML, heuristic), offline domain intelligence,
optional reputation, and prior threat intelligence - and combines them with the
pure ``combine_evidence`` policy into an :class:`IntelligenceReport`. The result
is persisted, audited, and auto-blacklisted when malicious.

The service depends only on Core ports and a pure domain policy; it never imports
a concrete model, provider, or the infrastructure. Sources are re-weighted from
configuration, and unavailable sources are simply excluded, so the engine
degrades gracefully.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from core.domain import (
    Evidence,
    EvidenceSource,
    ThreatCategory,
    Verdict,
    combine_evidence,
)
from core.domain.analysis import FeatureValue, UrlAnalysis
from core.domain.url import Url
from core.entities import ThreatEntry, UrlScan
from core.exceptions import ValidationError
from core.interfaces import (
    IAuditTrail,
    IDomainIntelligenceProvider,
    ILogger,
    IReputationProvider,
    IThreatProtectionService,
    IUnitOfWork,
    IUrlAnalyzer,
)
from services.pipeline import IntelligencePublisher

_ACTION = "url.analyze"
_MALICIOUS_VERDICTS = frozenset({Verdict.PHISHING})

_VERDICT_CATEGORY = {
    Verdict.PHISHING: ThreatCategory.PHISHING,
    Verdict.SUSPICIOUS: ThreatCategory.SUSPICIOUS_STRUCTURE,
    Verdict.LEGITIMATE: ThreatCategory.NONE,
}


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """The result of an analysis request.

    ``blacklisted`` means the URL is on the blacklist (freshly added or
    pre-existing); ``blacklist_hit`` means the analysis pipeline was skipped
    because the URL was already blacklisted.
    """

    scan: UrlScan
    blacklisted: bool
    blacklist_hit: bool


class UrlAnalysisService:
    """Application service that runs the hybrid URL intelligence engine."""

    def __init__(  # noqa: PLR0913 - a service assembled from many injected ports
        self,
        analyzers: Sequence[IUrlAnalyzer],
        domain_intelligence: IDomainIntelligenceProvider,
        reputation: IReputationProvider,
        threat_protection: IThreatProtectionService,
        unit_of_work_factory: Callable[[], IUnitOfWork],
        audit: IAuditTrail,
        logger: ILogger,
        *,
        weights: dict[EvidenceSource, float],
        suspicious_threshold: float,
        phishing_threshold: float,
        publisher: IntelligencePublisher | None = None,
    ) -> None:
        """Initialize the service.

        Args:
            analyzers: The URL analyzers (e.g. ML and heuristic) to combine.
            domain_intelligence: The domain intelligence provider.
            reputation: The reputation provider (may be disabled).
            threat_protection: The threat protection port (blacklist).
            unit_of_work_factory: Produces a Unit of Work for persistence.
            audit: The audit trail port.
            logger: Injected logger.
            weights: Per-source combination weights.
            suspicious_threshold: Score at/above which a URL is suspicious.
            phishing_threshold: Score at/above which a URL is phishing.
            publisher: Optional live-pipeline publisher; when provided, analysis
                results are published as intelligence events onto the event bus.
        """
        self._analyzers = tuple(analyzers)
        self._domain = domain_intelligence
        self._reputation = reputation
        self._threat = threat_protection
        self._unit_of_work_factory = unit_of_work_factory
        self._audit = audit
        self._logger = logger
        self._weights = weights
        self._suspicious_threshold = suspicious_threshold
        self._phishing_threshold = phishing_threshold
        self._publisher = publisher

    def analyze(self, raw_url: str, *, actor: str | None = None) -> ScanOutcome:
        """Analyze a URL through the hybrid engine and update the blacklist.

        Args:
            raw_url: The user-supplied URL.
            actor: Identifier of the requester, if known.

        Returns:
            The :class:`ScanOutcome`.

        Raises:
            ValidationError: If the URL is invalid.
        """
        try:
            url = Url.create(raw_url)
        except ValidationError:
            self._audit.failure(_ACTION, resource=raw_url, reason="invalid_url")
            raise

        # Blacklist first: a known threat short-circuits the whole pipeline.
        existing = self._threat.lookup(url)
        if existing is not None and existing.blocked:
            self._threat.register_hit(existing)
            scan = self._scan_from_threat(existing, actor)
            self._publish_scan(url, scan, malicious=True)
            return ScanOutcome(scan=scan, blacklisted=True, blacklist_hit=True)

        evidences, features = self._gather_evidence(url)
        report = combine_evidence(
            evidences,
            suspicious_threshold=self._suspicious_threshold,
            phishing_threshold=self._phishing_threshold,
            features=features,
        )
        scan = UrlScan.from_report(url, report, actor=actor)

        with self._unit_of_work_factory() as uow:
            uow.get_repository(UrlScan).add(scan)
            uow.commit()

        self._logger.info(
            "URL analyzed: {} -> {} ({}%) via {} sources",
            url.host,
            report.verdict.value,
            report.risk_percent,
            len(report.available_sources),
        )
        self._audit.success(
            _ACTION,
            resource=str(url),
            verdict=report.verdict.value,
            threat_score=report.risk_score,
            category=report.primary_category.value,
        )

        blacklisted = report.verdict in _MALICIOUS_VERDICTS
        if blacklisted:
            self._threat.record_detection(url, report.to_analysis())

        self._publish_scan(url, scan, malicious=blacklisted)
        return ScanOutcome(scan=scan, blacklisted=blacklisted, blacklist_hit=False)

    def _publish_scan(self, url: Url, scan: UrlScan, *, malicious: bool) -> None:
        """Publish analysis events for a URL scan (no-op without a publisher)."""
        if self._publisher is None:
            return
        self._publisher.analysis_completed(
            source="url-analysis",
            artifact_id=scan.url,
            artifact_type="url",
            verdict=scan.verdict.value,
            risk_score=scan.threat_score,
            category=scan.category.value,
            iocs=(url.host,),
            malicious=malicious,
        )

    def recent(self, limit: int = 10) -> list[UrlScan]:
        """Return the most recent scans, newest first.

        Args:
            limit: Maximum number of scans to return.

        Returns:
            Recent :class:`UrlScan` records.
        """
        with self._unit_of_work_factory() as uow:
            scans = uow.get_repository(UrlScan).list()
        scans.sort(key=lambda scan: scan.created_at, reverse=True)
        return scans[:limit]

    def _gather_evidence(self, url: Url) -> tuple[tuple[Evidence, ...], dict[str, FeatureValue]]:
        """Collect and re-weight evidence from every available source."""
        evidences: list[Evidence] = []
        features: dict[str, FeatureValue] = {}

        for analyzer in self._analyzers:
            analysis = analyzer.analyze(url)
            features.update(analysis.features)
            evidences.append(self._analyzer_evidence(analyzer.source, analysis))

        evidences.append(self._domain.assess(url))
        evidences.append(self._reputation.check(url))
        evidences.append(self._threat_intel_evidence())

        weighted = tuple(
            replace(e, weight=self._weights.get(e.source, e.weight)) for e in evidences
        )
        return weighted, features

    @staticmethod
    def _analyzer_evidence(source: EvidenceSource, analysis: UrlAnalysis) -> Evidence:
        return Evidence(
            source=source,
            risk=analysis.threat_score,
            confidence=analysis.confidence,
            weight=1.0,
            rationale=f"{source.value} analyzer score",
            category=_VERDICT_CATEGORY[analysis.verdict],
            contributions=analysis.triggered_contributions,
            available=True,
        )

    @staticmethod
    def _threat_intel_evidence() -> Evidence:
        # Reaching here means the URL was not blacklisted; record the clean signal.
        return Evidence(
            source=EvidenceSource.THREAT_INTEL,
            risk=0.0,
            confidence=0.9,
            weight=1.0,
            rationale="No prior detections in threat intelligence",
            category=ThreatCategory.NONE,
            contributions=(),
            available=True,
        )

    @staticmethod
    def _scan_from_threat(entry: ThreatEntry, actor: str | None) -> UrlScan:
        """Reconstruct a transient scan from a blacklist entry (no re-analysis)."""
        return UrlScan(
            url=entry.artifact,
            verdict=entry.verdict,
            threat_score=entry.risk_score,
            confidence=entry.confidence,
            features={},
            contributions=entry.indicators,
            category=ThreatCategory.PHISHING,
            actor=actor,
        )

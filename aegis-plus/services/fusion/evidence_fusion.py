"""Evidence Fusion Service.

The single source of truth for intelligence aggregation. It takes raw evidence
from multiple providers, deduplicates findings, preserves provider attribution
and confidence, computes overall severity, collects MITRE technique IDs and
analyst recommendations, tracks per-provider and total execution time, and
produces a :class:`FusionResult` that any intelligence engine can return.

The service delegates verdict/category/risk computation to the existing
``combine_evidence`` policy so the fusion layer is additive — it enriches, it
does not replace.
"""

from __future__ import annotations

import time

from core.domain.fusion import (
    FusionResult,
    IntelligenceRelationship,
    ProviderSummary,
    severity_from_score,
)
from core.domain.intelligence import (
    Evidence,
    ThreatCategory,
    combine_evidence,
)
from core.domain.ioc import IocCollection, ioc_statistics


class EvidenceFusionService:
    """Merges multi-provider evidence into an enriched fusion result."""

    def __init__(
        self,
        *,
        suspicious_threshold: float = 0.35,
        phishing_threshold: float = 0.65,
        fallback_category: ThreatCategory = ThreatCategory.PHISHING,
    ) -> None:
        """Initialize the fusion service with scoring thresholds."""
        self._suspicious = suspicious_threshold
        self._phishing = phishing_threshold
        self._fallback = fallback_category

    def fuse(
        self,
        evidences: tuple[Evidence, ...],
        *,
        ioc_collection: IocCollection | None = None,
        relationships: tuple[IntelligenceRelationship, ...] = (),
        fallback_category: ThreatCategory | None = None,
    ) -> FusionResult:
        """Fuse evidence into a single enriched intelligence result.

        Args:
            evidences: Raw evidence from all providers (may contain duplicates).
            ioc_collection: Extracted indicators for the IOC summary.
            relationships: Prepared Threat Graph edges.
            fallback_category: Override for the default fallback category.

        Returns:
            A :class:`FusionResult` with severity, recommendations, MITRE
            technique IDs, IOC summary, and provider summaries.
        """
        start = time.monotonic()
        deduped = self._deduplicate(evidences)
        report = combine_evidence(
            deduped,
            suspicious_threshold=self._suspicious,
            phishing_threshold=self._phishing,
            fallback_category=fallback_category or self._fallback,
        )
        elapsed = (time.monotonic() - start) * 1000

        provider_summaries = self._provider_summaries(deduped)
        recommendations = self._collect_recommendations(deduped)
        technique_ids = self._collect_techniques(deduped)
        total_duration = sum(e.execution_ms for e in deduped) + elapsed
        iocs = ioc_collection or IocCollection()

        return FusionResult(
            report=report,
            severity=severity_from_score(report.risk_score),
            analysis_duration_ms=round(total_duration, 2),
            recommendations=recommendations,
            technique_ids=technique_ids,
            ioc_summary=ioc_statistics(iocs),
            provider_summaries=provider_summaries,
            relationships=relationships,
            ioc_collection=iocs,
        )

    @staticmethod
    def _deduplicate(evidences: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
        """Remove duplicate evidence based on source + rationale + risk."""
        seen: dict[str, None] = {}
        unique: list[Evidence] = []
        for evidence in evidences:
            key = f"{evidence.source.value}:{evidence.rationale}:{evidence.risk}"
            if key not in seen:
                seen[key] = None
                unique.append(evidence)
        return tuple(unique)

    @staticmethod
    def _provider_summaries(evidences: tuple[Evidence, ...]) -> tuple[ProviderSummary, ...]:
        """Build a per-provider summary from the evidence set."""
        summaries: list[ProviderSummary] = []
        for evidence in evidences:
            if not evidence.provider_name:
                continue
            summaries.append(
                ProviderSummary(
                    name=evidence.provider_name,
                    version=evidence.provider_version,
                    execution_ms=evidence.execution_ms,
                    evidence_count=len(evidence.contributions),
                    risk=round(evidence.risk, 4),
                    confidence=round(evidence.confidence, 4),
                    technique_ids=evidence.technique_ids,
                )
            )
        return tuple(summaries)

    @staticmethod
    def _collect_recommendations(evidences: tuple[Evidence, ...]) -> tuple[str, ...]:
        """Gather unique analyst recommendations from all contributions."""
        recs: dict[str, None] = {}
        for evidence in evidences:
            for contribution in evidence.contributions:
                if contribution.recommendation and contribution.triggered:
                    recs[contribution.recommendation] = None
        return tuple(recs)

    @staticmethod
    def _collect_techniques(evidences: tuple[Evidence, ...]) -> tuple[str, ...]:
        """Gather unique MITRE ATT&CK technique IDs across all evidence."""
        techniques: dict[str, None] = {}
        for evidence in evidences:
            for tid in evidence.technique_ids:
                if tid:
                    techniques[tid] = None
            for contribution in evidence.contributions:
                if contribution.technique_id:
                    techniques[contribution.technique_id] = None
        return tuple(techniques)

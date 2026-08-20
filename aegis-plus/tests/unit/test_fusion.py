"""Tests for the Intelligence Fusion Layer (M8-P2b)."""

from __future__ import annotations

from core.domain.analysis import FeatureContribution
from core.domain.fusion import (
    FusionResult,
    IntelligenceRelationship,
    ProviderInfo,
    Severity,
    severity_from_score,
)
from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    ThreatCategory,
)
from core.domain.ioc import IocCollection
from services.fusion import EvidenceFusionService, IOCFusionService, ProviderRegistry

# --- Severity ---


def test_severity_from_score_maps_correctly() -> None:
    assert severity_from_score(0.90) is Severity.CRITICAL
    assert severity_from_score(0.70) is Severity.HIGH
    assert severity_from_score(0.45) is Severity.MEDIUM
    assert severity_from_score(0.10) is Severity.LOW
    assert severity_from_score(0.0) is Severity.INFO


# --- Evidence Fusion ---


def _evidence(
    source: EvidenceSource,
    risk: float,
    name: str = "",
    technique: str = "",
    recommendation: str = "",
) -> Evidence:
    contributions: tuple[FeatureContribution, ...] = ()
    if recommendation:
        contributions = (FeatureContribution("f", "d", risk, True, recommendation=recommendation),)
    return Evidence(
        source=source,
        risk=risk,
        confidence=0.8,
        weight=1.0,
        rationale=f"test-{name}",
        category=ThreatCategory.PHISHING if risk > 0.5 else ThreatCategory.NONE,
        provider_name=name,
        provider_version="1.0.0",
        execution_ms=1.5,
        technique_ids=(technique,) if technique else (),
        contributions=contributions,
    )


def test_evidence_fusion_produces_fusion_result() -> None:
    svc = EvidenceFusionService()
    evidences = (
        _evidence(EvidenceSource.FILE_SCRIPT, 0.8, "ScriptProvider", "T1059"),
        _evidence(EvidenceSource.FILE_STRUCTURE, 0.7, "StructureProvider"),
    )
    result = svc.fuse(evidences)
    assert isinstance(result, FusionResult)
    assert result.severity is Severity.CRITICAL
    assert result.analysis_duration_ms > 0
    assert len(result.provider_summaries) == 2
    assert "T1059" in result.technique_ids


def test_evidence_fusion_deduplicates() -> None:
    svc = EvidenceFusionService()
    e = _evidence(EvidenceSource.FILE_SCRIPT, 0.8, "ScriptProvider")
    result = svc.fuse((e, e, e))
    assert len(result.provider_summaries) == 1


def test_evidence_fusion_collects_recommendations() -> None:
    svc = EvidenceFusionService()
    evidences = (
        _evidence(EvidenceSource.FILE_SCRIPT, 0.8, "A", recommendation="Disable macros"),
        _evidence(EvidenceSource.FILE_STRUCTURE, 0.7, "B", recommendation="Quarantine file"),
    )
    result = svc.fuse(evidences)
    assert "Disable macros" in result.recommendations
    assert "Quarantine file" in result.recommendations


def test_evidence_fusion_with_ioc_summary() -> None:
    svc = EvidenceFusionService()
    iocs = IocCollection(urls=("http://evil.com",), ipv4_addresses=("10.0.0.1",))
    result = svc.fuse(
        (_evidence(EvidenceSource.FILE_ARCHIVE, 0.3, "IndicatorProvider"),),
        ioc_collection=iocs,
    )
    assert result.ioc_summary.url_count == 1
    assert result.ioc_summary.ipv4_count == 1
    assert result.ioc_summary.total == 2


def test_evidence_fusion_preserves_relationships() -> None:
    svc = EvidenceFusionService()
    rels = (IntelligenceRelationship("a", "file", "b", "url", "contains"),)
    result = svc.fuse(
        (_evidence(EvidenceSource.FILE_SCRIPT, 0.5, "A"),),
        relationships=rels,
    )
    assert len(result.relationships) == 1
    assert result.relationships[0].relationship == "contains"


# --- Provider Registry ---


def test_provider_registry_registers_and_queries() -> None:
    registry = ProviderRegistry()
    registry.register(
        ProviderInfo(name="TestProvider", version="1.0.0", supported_artifact_types=("file",))
    )
    assert registry.count == 1
    assert registry.get("TestProvider") is not None
    assert registry.get("missing") is None


def test_provider_registry_filters_enabled() -> None:
    registry = ProviderRegistry()
    registry.register(ProviderInfo(name="A", version="1", enabled=True))
    registry.register(ProviderInfo(name="B", version="1", enabled=False))
    assert len(registry.enabled()) == 1
    assert registry.enabled()[0].name == "A"


def test_provider_registry_summary() -> None:
    registry = ProviderRegistry()
    registry.register(ProviderInfo(name="A", version="2.0"))
    summary = registry.summary()
    assert summary["A"] == "2.0 (enabled)"


# --- IOC Fusion ---


def test_ioc_fusion_merges_collections() -> None:
    svc = IOCFusionService()
    a = IocCollection(urls=("http://a.com",), domains=("a.com",))
    b = IocCollection(urls=("http://b.com",), domains=("a.com",))
    merged = svc.merge(a, b)
    assert set(merged.urls) == {"http://a.com", "http://b.com"}
    assert merged.domains == ("a.com",)


def test_ioc_fusion_extracts_relationships() -> None:
    svc = IOCFusionService()
    iocs = IocCollection(urls=("http://evil.com",), ipv4_addresses=("10.0.0.1",))
    rels = svc.extract_relationships("scan-1", "file", iocs)
    assert len(rels) >= 2
    assert all(r.source_id == "scan-1" for r in rels)
    assert all(r.relationship == "contains" for r in rels)


def test_ioc_fusion_cross_correlates() -> None:
    svc = IOCFusionService()
    collections = {
        "email-1": IocCollection(urls=("http://evil.com",)),
        "file-1": IocCollection(urls=("http://evil.com",)),
        "file-2": IocCollection(urls=("http://other.com",)),
    }
    rels = svc.cross_correlate(collections)
    # email-1 and file-1 share http://evil.com → should produce a shares_ioc edge
    shared = [r for r in rels if r.relationship == "shares_ioc"]
    assert len(shared) >= 1
    ids = {r.source_id for r in shared} | {r.target_id for r in shared}
    assert "email-1" in ids
    assert "file-1" in ids


def test_ioc_fusion_no_correlation_without_overlap() -> None:
    svc = IOCFusionService()
    collections = {
        "a": IocCollection(urls=("http://a.com",)),
        "b": IocCollection(urls=("http://b.com",)),
    }
    assert svc.cross_correlate(collections) == ()


# --- Relationship model ---


def test_relationship_key_is_deterministic() -> None:
    r = IntelligenceRelationship("a", "file", "b", "url", "contains")
    assert r.key == "file:a->contains->url:b"


# --- Integration-level: fusion through the full file engine ---


def test_file_analysis_produces_fusion_compatible_evidence() -> None:
    """Evidence from file providers carries the metadata fusion requires."""
    from ai.file_analysis import ScriptProvider, StructureProvider
    from services.file_analysis.ingestion import FileIngestor

    artifact = FileIngestor().ingest(
        "evil.pdf.exe", b"MZ\x90\x00" + b"\x00" * 60 + b"eval(FromBase64String('...'))"
    )
    structure_evidence = StructureProvider().assess(artifact)
    script_evidence = ScriptProvider().assess(artifact)

    # Provider metadata present
    assert structure_evidence.provider_name == "StructureProvider"
    assert script_evidence.provider_name == "ScriptProvider"
    assert structure_evidence.provider_version
    assert script_evidence.execution_ms >= 0

    # Fusion service can consume them
    svc = EvidenceFusionService()
    result = svc.fuse(
        (structure_evidence, script_evidence),
        ioc_collection=artifact.indicators,
    )
    assert isinstance(result, FusionResult)
    assert result.severity in (Severity.CRITICAL, Severity.HIGH)
    assert len(result.provider_summaries) == 2


def test_multi_artifact_correlation_through_ioc_fusion() -> None:
    """Email and file sharing a URL are linked by the IOC fusion service."""
    from core.domain.ioc import extract_iocs

    email_iocs = extract_iocs("Click here: http://evil.example.com/phish")
    file_iocs = extract_iocs("dropper URL: http://evil.example.com/phish and http://other.com")

    svc = IOCFusionService()
    merged = svc.merge(email_iocs, file_iocs)
    assert "http://evil.example.com/phish" in merged.urls

    rels = svc.cross_correlate({"email-scan-1": email_iocs, "file-scan-1": file_iocs})
    shared = [r for r in rels if r.relationship == "shares_ioc"]
    assert len(shared) >= 1

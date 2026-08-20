"""Unit tests for the offline file evidence providers and hybrid analyzer."""

from __future__ import annotations

from ai.file_analysis import (
    EntropyProvider,
    HybridFileAnalyzer,
    IndicatorProvider,
    MetadataProvider,
    ScriptProvider,
    StructureProvider,
)
from core.domain.analysis import Verdict
from core.domain.intelligence import EvidenceSource, ThreatCategory
from services.file_analysis.ingestion import FileIngestor

_INGEST = FileIngestor()


def _analyzer() -> HybridFileAnalyzer:
    return HybridFileAnalyzer(
        [
            StructureProvider(),
            EntropyProvider(),
            MetadataProvider(),
            ScriptProvider(),
            IndicatorProvider(),
        ],
        weights={
            EvidenceSource.FILE_STRUCTURE: 1.2,
            EvidenceSource.FILE_SCRIPT: 1.3,
            EvidenceSource.FILE_METADATA: 1.1,
        },
        suspicious_threshold=0.35,
        phishing_threshold=0.65,
    )


def test_structure_provider_flags_double_extension() -> None:
    artifact = _INGEST.ingest("invoice.pdf.exe", b"MZ\x90\x00" + b"\x00" * 60)
    evidence = StructureProvider().assess(artifact)
    assert evidence.risk >= 0.85
    assert evidence.category is ThreatCategory.MALWARE_DELIVERY


def test_entropy_provider_flags_high_entropy() -> None:
    artifact = _INGEST.ingest("packed.bin", bytes(range(256)) * 40)
    evidence = EntropyProvider().assess(artifact)
    assert evidence.risk > 0.0
    assert evidence.category is ThreatCategory.NONE  # entropy never names a category


def test_script_provider_detects_macros() -> None:
    data = b'\xd0\xcf\x11\xe0 Auto_Open Shell("cmd.exe") vba_project'
    artifact = _INGEST.ingest("macro.doc", data)
    evidence = ScriptProvider().assess(artifact)
    assert evidence.category is ThreatCategory.MALICIOUS_DOCUMENT


def test_script_provider_detects_scripts() -> None:
    data = b"eval(FromBase64String('...')); new ActiveXObject('WScript.Shell')"
    artifact = _INGEST.ingest("dropper.js", data)
    evidence = ScriptProvider().assess(artifact)
    assert evidence.category is ThreatCategory.MALICIOUS_SCRIPT


def test_metadata_provider_flags_executable() -> None:
    artifact = _INGEST.ingest("tool.exe", b"MZ\x90\x00" + b"\x00" * 60)
    evidence = MetadataProvider().assess(artifact)
    assert evidence.category is ThreatCategory.SUSPICIOUS_EXECUTABLE


def test_analyzer_malicious_document() -> None:
    data = b'\xd0\xcf\x11\xe0 Auto_Open Shell("cmd.exe") vba_project macros/vba'
    report = _analyzer().analyze(_INGEST.ingest("macro.docm", data))
    assert report.verdict is Verdict.PHISHING
    assert report.primary_category is ThreatCategory.MALICIOUS_DOCUMENT


def test_analyzer_double_extension_executable() -> None:
    data = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
    report = _analyzer().analyze(_INGEST.ingest("invoice.pdf.exe", data))
    assert report.verdict is Verdict.PHISHING
    assert report.primary_category is ThreatCategory.MALWARE_DELIVERY


def test_analyzer_benign_text_is_legitimate() -> None:
    data = b"Quarterly report. Visit https://legit.example.com. Contact ceo@corp.com."
    report = _analyzer().analyze(_INGEST.ingest("report.txt", data))
    assert report.verdict is Verdict.LEGITIMATE


def test_analyzer_high_entropy_only_is_structural() -> None:
    report = _analyzer().analyze(_INGEST.ingest("packed.bin", bytes(range(256)) * 80))
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.primary_category is ThreatCategory.SUSPICIOUS_STRUCTURE

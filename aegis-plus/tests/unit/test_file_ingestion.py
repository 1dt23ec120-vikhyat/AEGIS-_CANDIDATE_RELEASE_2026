"""Unit tests for file ingestion into a byte-free artifact."""

from __future__ import annotations

import pytest

from core.exceptions import ValidationError
from services.file_analysis.ingestion import FileIngestor


def test_ingest_computes_fingerprints_and_type() -> None:
    artifact = FileIngestor().ingest("a.zip", b"PK\x03\x04rest of the archive")
    assert artifact.fingerprints.sha256
    assert artifact.file_type.kind.value == "archive"
    assert artifact.size == len(b"PK\x03\x04rest of the archive")


def test_ingest_extracts_indicators_from_preview() -> None:
    artifact = FileIngestor().ingest("note.txt", b"contact http://evil.example.com or a@b.com")
    assert "http://evil.example.com" in artifact.indicators.urls
    assert "a@b.com" in artifact.indicators.emails


def test_ingest_rejects_empty_file() -> None:
    with pytest.raises(ValidationError):
        FileIngestor().ingest("empty.bin", b"")


def test_ingest_enforces_size_cap() -> None:
    with pytest.raises(ValidationError):
        FileIngestor(max_bytes=10).ingest("big.bin", b"x" * 11)


def test_ingest_sanitizes_filename() -> None:
    artifact = FileIngestor().ingest("../../etc/passwd", b"root:x:0:0")
    assert artifact.filename == "passwd"


def test_ingest_never_exposes_raw_bytes() -> None:
    artifact = FileIngestor().ingest("a.bin", b"secret bytes")
    # The artifact is byte-free: it exposes only derived facts.
    assert not hasattr(artifact, "data")
    assert not hasattr(artifact, "raw")

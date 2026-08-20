"""Unit tests for the file artifact domain model and fingerprint registry."""

from __future__ import annotations

import hashlib

from core.domain.file import (
    DEFAULT_FINGERPRINT_PROVIDERS,
    FileKind,
    Fingerprint,
    FingerprintSet,
    compute_fingerprints,
    describe_metadata,
    has_double_extension,
    identify_type,
    shannon_entropy,
    split_extension,
    validate_filename,
)


def test_compute_fingerprints_matches_hashlib() -> None:
    data = b"hello world"
    fingerprints = compute_fingerprints(data)
    assert fingerprints.sha256 == hashlib.sha256(data).hexdigest()
    assert fingerprints.sha1 == hashlib.sha1(data).hexdigest()
    assert fingerprints.md5 == hashlib.md5(data).hexdigest()


def test_fingerprint_registry_is_extensible() -> None:
    # A custom provider can be added without changing the domain model.
    def constant_provider(_: bytes) -> Fingerprint:
        return Fingerprint(algorithm="demo", value="fixed")

    providers = (*DEFAULT_FINGERPRINT_PROVIDERS, constant_provider)
    result = compute_fingerprints(b"x", providers)
    assert result.value("demo") == "fixed"
    assert result.sha256  # existing providers still run


def test_fingerprint_set_as_dict() -> None:
    fs = FingerprintSet(fingerprints=(Fingerprint("sha256", "aa"), Fingerprint("md5", "bb")))
    assert fs.as_dict() == {"sha256": "aa", "md5": "bb"}
    assert fs.value("absent") == ""


def test_shannon_entropy_bounds() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert shannon_entropy(bytes(range(256))) > 7.9


def test_split_and_double_extension() -> None:
    assert split_extension("invoice.PDF") == ".pdf"
    assert split_extension("noext") == ""
    assert has_double_extension("invoice.pdf.exe") is True
    assert has_double_extension("archive.tar.gz") is False
    assert has_double_extension("report.pdf") is False


def test_identify_type_from_magic() -> None:
    assert identify_type("a.exe", b"MZ\x90\x00").kind is FileKind.EXECUTABLE
    assert identify_type("a.zip", b"PK\x03\x04").kind is FileKind.ARCHIVE
    assert identify_type("a.pdf", b"%PDF-1.7").kind is FileKind.DOCUMENT
    assert identify_type("a.png", b"\x89PNG\r\n").kind is FileKind.IMAGE


def test_identify_type_mime_mismatch() -> None:
    # Declares .pdf but content is a PE executable.
    file_type = identify_type("invoice.pdf", b"MZ\x90\x00")
    assert file_type.mime_mismatch is True


def test_describe_metadata_flags_executable() -> None:
    metadata = describe_metadata("x.exe", b"MZ\x90\x00", identify_type("x.exe", b"MZ"))
    assert metadata.is_executable is True
    assert metadata.has_dangerous_extension is True


def test_validate_filename_strips_path_components() -> None:
    assert validate_filename("../../etc/passwd") == "passwd"
    assert validate_filename("C:\\Windows\\evil.exe") == "evil.exe"
    assert validate_filename("") == "unnamed"

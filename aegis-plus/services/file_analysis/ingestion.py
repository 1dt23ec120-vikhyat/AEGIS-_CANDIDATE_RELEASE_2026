"""File ingestion.

Turns raw uploaded bytes into a byte-free :class:`AnalyzedArtifact`: it computes
fingerprints, identifies the type, measures entropy, extracts a bounded text
preview and its indicators of compromise, and describes structural metadata.
For ZIP archives it reads the entry list in-memory (never extracting to disk).
For PE executables it runs the static PE parser to produce a :class:`PEInfo`.

This is the one place raw bytes are handled; everything downstream operates on
the derived artifact, and the bytes are released as soon as ingestion returns.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from io import BytesIO

from core.domain.file import (
    ArchiveEntry,
    EntropyProfile,
    PEInfo,
    compute_fingerprints,
    describe_metadata,
    identify_type,
    shannon_entropy,
    validate_filename,
)
from core.domain.ioc import IocCollection, extract_iocs
from core.domain.pe import parse_pe
from core.exceptions import ValidationError
from core.interfaces import AnalyzedArtifact, IPeParser

_DEFAULT_MAX_BYTES = 25 * 1024 * 1024
_HEADER_BYTES = 64
_PREVIEW_BYTES = 1_000_000
_ENTROPY_SAMPLE = 1_000_000
_MAX_ARCHIVE_ENTRIES = 10_000

_DANGEROUS_EXTENSIONS = frozenset(
    {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".hta"}
)


@dataclass(frozen=True, slots=True)
class FileIngestor:
    """Builds a byte-free analyzed artifact from raw upload bytes.

    The PE parser is injected through the Core :class:`IPeParser` port
    (Dependency Inversion). When none is supplied, the pure
    :func:`core.domain.pe.parse_pe` default is used, so a bare ``FileIngestor()``
    behaves exactly as before.
    """

    max_bytes: int = _DEFAULT_MAX_BYTES
    pe_parser: IPeParser | None = None

    def ingest(self, filename: str, data: bytes) -> AnalyzedArtifact:
        """Ingest raw bytes into an :class:`AnalyzedArtifact`.

        Args:
            filename: The client-supplied filename (sanitized here).
            data: The raw file bytes (not retained after this call).

        Returns:
            The derived, byte-free artifact.

        Raises:
            ValidationError: If the file is empty or exceeds the size cap.
        """
        if not data:
            raise ValidationError("Uploaded file is empty")
        if len(data) > self.max_bytes:
            raise ValidationError(f"File exceeds the {self.max_bytes} byte analysis limit")

        safe_name = validate_filename(filename)
        header = data[:_HEADER_BYTES]
        fingerprints = compute_fingerprints(data)
        file_type = identify_type(safe_name, header)
        metadata = describe_metadata(safe_name, header, file_type)
        entropy = EntropyProfile(entropy=shannon_entropy(data[:_ENTROPY_SAMPLE]))
        preview = self._text_preview(data)
        indicators = extract_iocs(preview) if preview else IocCollection()
        archive_entries = self._extract_archive_entries(data, file_type.kind.value)
        pe_info = self._parse_pe(data, metadata.is_executable)

        return AnalyzedArtifact(
            filename=safe_name,
            size=len(data),
            fingerprints=fingerprints,
            file_type=file_type,
            metadata=metadata,
            entropy=entropy,
            indicators=indicators,
            text_preview=preview,
            archive_entries=archive_entries,
            pe_info=pe_info,
        )

    @staticmethod
    def _text_preview(data: bytes) -> str:
        """Decode a bounded, lossy text preview for indicator extraction."""
        return data[:_PREVIEW_BYTES].decode("utf-8", errors="replace")

    @staticmethod
    def _extract_archive_entries(data: bytes, kind: str) -> tuple[ArchiveEntry, ...]:
        """Read the ZIP entry list in-memory without extracting to disk."""
        if kind != "archive" and data[:4] != b"PK\x03\x04":
            return ()
        entries: list[ArchiveEntry] = []
        try:
            with zipfile.ZipFile(BytesIO(data), "r") as zf:
                for info in zf.infolist()[:_MAX_ARCHIVE_ENTRIES]:
                    if info.is_dir():
                        continue
                    ext = (
                        ("." + info.filename.rsplit(".", 1)[-1]).lower()
                        if "." in info.filename
                        else ""
                    )
                    entries.append(
                        ArchiveEntry(
                            name=info.filename,
                            size=info.file_size,
                            compressed_size=info.compress_size,
                            is_dangerous=ext in _DANGEROUS_EXTENSIONS,
                            has_traversal=".." in info.filename or info.filename.startswith("/"),
                        )
                    )
        except (zipfile.BadZipFile, OSError):
            pass
        return tuple(entries)

    def _parse_pe(self, data: bytes, is_executable: bool) -> PEInfo | None:
        """Parse PE metadata if the file looks like an executable.

        Uses the injected :class:`IPeParser` when provided, otherwise the pure
        core default — behaviour is identical either way.
        """
        if not is_executable and data[:2] != b"MZ":
            return None
        if self.pe_parser is not None:
            return self.pe_parser.parse(data)
        return parse_pe(data)

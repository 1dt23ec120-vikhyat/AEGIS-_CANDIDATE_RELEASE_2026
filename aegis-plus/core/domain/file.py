"""File artifact domain model.

Framework-independent value objects describing an analyzed file, plus the
fingerprinting extension seam. The design is artifact-first: the fingerprint
registry and the analysis contracts are expressed in terms of *artifact bytes*,
so future artifact types (memory dumps, registry exports, PCAPs, ...) can reuse
the same machinery. The file is simply the first such artifact.

Depends only on the standard library (``hashlib``, ``math``, ``re``, ``struct``,
``enum``), preserving domain purity. Uploaded bytes are handled transiently by
callers and never stored on any value object beyond the scope of analysis.
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

_ENTROPY_BASE = 256
_HIGH_ENTROPY = 7.2
_MODERATE_ENTROPY = 6.0
_MAX_NAME = 255
_PRINTABLE_LOW = 0x20
_PRINTABLE_HIGH = 0x7F
_TEXT_RATIO = 0.85

# Magic byte signatures for offline type identification. Kept deliberately small
# and additive - new signatures extend the tuple without touching callers.
_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "application/x-dosexec", "executable"),
    (b"\x7fELF", "application/x-elf", "executable"),
    (b"PK\x03\x04", "application/zip", "archive"),
    (b"%PDF", "application/pdf", "document"),
    (b"\xd0\xcf\x11\xe0", "application/x-ole-storage", "document"),
    (b"\x1f\x8b", "application/gzip", "archive"),
    (b"Rar!\x1a\x07", "application/x-rar", "archive"),
    (b"\x89PNG", "image/png", "image"),
    (b"GIF8", "image/gif", "image"),
    (b"\xff\xd8\xff", "image/jpeg", "image"),
)

_EXTENSION_MIME: dict[str, str] = {
    ".exe": "application/x-dosexec",
    ".dll": "application/x-dosexec",
    ".zip": "application/zip",
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".js": "text/javascript",
    ".vbs": "text/vbscript",
    ".ps1": "text/x-powershell",
    ".sh": "text/x-shellscript",
    ".txt": "text/plain",
}

_DANGEROUS_EXTENSIONS = frozenset(
    {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".hta"}
)
_ARCHIVE_EXTENSIONS = frozenset({".zip", ".rar", ".7z", ".gz", ".tar"})
_SCRIPT_EXTENSIONS = frozenset({".js", ".vbs", ".ps1", ".sh", ".bat", ".cmd", ".py"})


class FileKind(str, Enum):
    """A coarse classification of a file's nature."""

    EXECUTABLE = "executable"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    SCRIPT = "script"
    IMAGE = "image"
    DATA = "data"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """A single named fingerprint value produced by a provider."""

    algorithm: str
    value: str


@dataclass(frozen=True, slots=True)
class FingerprintSet:
    """The fingerprints computed for an artifact, keyed by algorithm."""

    fingerprints: tuple[Fingerprint, ...] = ()

    def value(self, algorithm: str) -> str:
        """Return the value for ``algorithm``, or an empty string if absent."""
        for fingerprint in self.fingerprints:
            if fingerprint.algorithm == algorithm:
                return fingerprint.value
        return ""

    @property
    def sha256(self) -> str:
        """The SHA-256 digest, the platform's primary artifact identity."""
        return self.value("sha256")

    @property
    def sha1(self) -> str:
        """The SHA-1 digest."""
        return self.value("sha1")

    @property
    def md5(self) -> str:
        """The MD5 digest."""
        return self.value("md5")

    def as_dict(self) -> dict[str, str]:
        """Return the fingerprints as an ``algorithm -> value`` mapping."""
        return {fp.algorithm: fp.value for fp in self.fingerprints}


# A fingerprint provider maps artifact bytes to a fingerprint. Providers are the
# extension seam: SSDEEP, TLSH, IMPHASH, Authenticode, and others register here
# without any change to the domain model or callers.
FingerprintProvider = Callable[[bytes], Fingerprint]


def _hash_provider(algorithm: str) -> FingerprintProvider:
    def provider(data: bytes) -> Fingerprint:
        digest = hashlib.new(algorithm, data).hexdigest()
        return Fingerprint(algorithm=algorithm, value=digest)

    return provider


# The default registry. Only cryptographic hashes are implemented now; the list
# is ordered and additive, so fuzzy/import/signature hashes slot in later.
DEFAULT_FINGERPRINT_PROVIDERS: tuple[FingerprintProvider, ...] = (
    _hash_provider("sha256"),
    _hash_provider("sha1"),
    _hash_provider("md5"),
)


def compute_fingerprints(
    data: bytes, providers: tuple[FingerprintProvider, ...] | None = None
) -> FingerprintSet:
    """Compute all registered fingerprints for ``data``.

    Args:
        data: The artifact bytes (held only for the duration of the call).
        providers: Optional override of the provider registry; defaults to the
            platform registry of SHA-256, SHA-1 and MD5.

    Returns:
        The computed :class:`FingerprintSet`.
    """
    registry = providers if providers is not None else DEFAULT_FINGERPRINT_PROVIDERS
    return FingerprintSet(fingerprints=tuple(provider(data) for provider in registry))


@dataclass(frozen=True, slots=True)
class FileType:
    """The identified type of a file."""

    extension: str
    declared_mime: str
    detected_mime: str
    kind: FileKind

    @property
    def mime_mismatch(self) -> bool:
        """Whether the extension-declared MIME disagrees with the detected one."""
        if not self.declared_mime or not self.detected_mime:
            return False
        return self.declared_mime != self.detected_mime


@dataclass(frozen=True, slots=True)
class EntropyProfile:
    """Shannon entropy of an artifact and its interpretation."""

    entropy: float

    @property
    def is_high(self) -> bool:
        """Whether entropy suggests packing, compression or encryption."""
        return self.entropy >= _HIGH_ENTROPY

    @property
    def is_moderate(self) -> bool:
        """Whether entropy is elevated but not conclusively high."""
        return _MODERATE_ENTROPY <= self.entropy < _HIGH_ENTROPY

    @property
    def descriptor(self) -> str:
        """A short human-readable descriptor of the entropy level."""
        if self.is_high:
            return "high (packed/encrypted)"
        if self.is_moderate:
            return "moderate"
        return "low"


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    """Metadata for a single entry inside an inspected archive."""

    name: str
    size: int
    compressed_size: int
    is_dangerous: bool
    has_traversal: bool


@dataclass(frozen=True, slots=True)
class PESection:
    """A single PE section header."""

    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    is_suspicious: bool


@dataclass(frozen=True, slots=True)
class PEImport:
    """A single imported DLL and the functions it exposes."""

    dll_name: str
    functions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PEInfo:
    """Parsed PE metadata for an executable artifact.

    Parsed by ``struct`` from the raw header bytes; no ``pefile`` dependency.
    All fields are derived and byte-free. A future ``pefile``-based parser
    produces the same VO, swapping only the parsing layer.
    """

    is_pe: bool = False
    is_64bit: bool = False
    compile_timestamp: int = 0
    num_sections: int = 0
    sections: tuple[PESection, ...] = ()
    imports: tuple[PEImport, ...] = ()
    has_exports: bool = False
    has_signature: bool = False
    has_debug: bool = False
    entry_point: int = 0
    image_base: int = 0
    subsystem: int = 0
    characteristics: int = 0
    suspicious_section_names: tuple[str, ...] = ()
    packer_indicators: tuple[str, ...] = ()
    version_company: str = ""
    version_product: str = ""
    version_description: str = ""


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """Structural findings gathered without executing the file."""

    kind: FileKind
    has_dangerous_extension: bool
    has_double_extension: bool
    is_script: bool
    is_archive: bool
    is_executable: bool
    detail: tuple[str, ...] = field(default_factory=tuple)


def shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of ``data`` in bits per byte.

    Args:
        data: The bytes to measure.

    Returns:
        Entropy in the range ``[0, 8]``; ``0.0`` for empty input.
    """
    if not data:
        return 0.0
    counts = [0] * _ENTROPY_BASE
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def split_extension(filename: str) -> str:
    """Return the lowercased final extension of ``filename`` (including dot)."""
    name = filename.strip().lower()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1]


def has_double_extension(filename: str) -> bool:
    """Whether ``filename`` hides a dangerous extension behind a benign one."""
    parts = filename.strip().lower().split(".")
    if len(parts) < 3:  # noqa: PLR2004 - name + two extension segments
        return False
    final = "." + parts[-1]
    penultimate = "." + parts[-2]
    benign_cover = penultimate not in _DANGEROUS_EXTENSIONS
    return final in _DANGEROUS_EXTENSIONS and benign_cover


def identify_type(filename: str, header: bytes) -> FileType:
    """Identify a file's type from its name and leading bytes.

    Args:
        filename: The original filename (for the declared extension/MIME).
        header: The leading bytes of the file for magic-signature matching.

    Returns:
        The identified :class:`FileType`.
    """
    extension = split_extension(filename)
    declared = _EXTENSION_MIME.get(extension, "")
    detected = ""
    kind = FileKind.UNKNOWN
    for signature, mime, kind_name in _SIGNATURES:
        if header.startswith(signature):
            detected = mime
            kind = FileKind(kind_name)
            break
    if kind is FileKind.UNKNOWN:
        if extension in _SCRIPT_EXTENSIONS:
            kind = FileKind.SCRIPT
        elif extension in _ARCHIVE_EXTENSIONS:
            kind = FileKind.ARCHIVE
        elif _is_text(header):
            kind = FileKind.DATA
    return FileType(
        extension=extension,
        declared_mime=declared,
        detected_mime=detected,
        kind=kind,
    )


def describe_metadata(filename: str, header: bytes, file_type: FileType) -> FileMetadata:
    """Summarize structural findings for a file without executing it."""
    extension = split_extension(filename)
    is_executable = header.startswith((b"MZ", b"\x7fELF"))
    detail: list[str] = []
    if is_executable and header.startswith(b"MZ"):
        detail.append(_pe_summary(header))
    return FileMetadata(
        kind=file_type.kind,
        has_dangerous_extension=extension in _DANGEROUS_EXTENSIONS,
        has_double_extension=has_double_extension(filename),
        is_script=extension in _SCRIPT_EXTENSIONS or file_type.kind is FileKind.SCRIPT,
        is_archive=extension in _ARCHIVE_EXTENSIONS or file_type.kind is FileKind.ARCHIVE,
        is_executable=is_executable,
        detail=tuple(detail),
    )


def _pe_summary(header: bytes) -> str:
    """Best-effort description of a DOS/PE header without parsing sections."""
    if len(header) < 0x40:  # noqa: PLR2004 - DOS header size
        return "DOS/PE executable (truncated header)"
    try:
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    except struct.error:
        return "DOS/PE executable"
    if 0 < pe_offset < len(header) - 4 and header[pe_offset : pe_offset + 4] == b"PE\x00\x00":
        return "PE executable (Windows portable executable)"
    return "DOS/MZ executable"


def _is_text(header: bytes) -> bool:
    if not header:
        return False
    printable = sum(
        1 for byte in header if _PRINTABLE_LOW <= byte < _PRINTABLE_HIGH or byte in (9, 10, 13)
    )
    return printable / len(header) > _TEXT_RATIO


def validate_filename(filename: str) -> str:
    """Return a safe, bounded filename, rejecting path components.

    Uploaded names are untrusted; any directory component is stripped so a
    malicious name cannot influence storage or logging paths.
    """
    name = filename.strip().replace("\\", "/").split("/")[-1]
    return name[:_MAX_NAME] if name else "unnamed"

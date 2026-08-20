"""File analyzer ports.

Contracts for the file intelligence engine, mirroring the URL and email analyzer
designs. The contracts are expressed against an :class:`AnalyzedArtifact` rather
than a file specifically, so the same ports can serve future artifact types
(memory dumps, registry exports, PCAPs) without change; the file is the first
artifact.

An :class:`IArtifactEvidenceProvider` contributes one source of evidence about an
artifact; an :class:`IFileAnalyzer` combines provider evidence (plus any evidence
supplied by the caller, such as embedded-URL results) into a report. An
:class:`IArchiveInspector` is the extension seam for future deep archive
inspection. Owned by Core so services depend only on these abstractions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from core.domain.file import (
    ArchiveEntry,
    EntropyProfile,
    FileMetadata,
    FileType,
    FingerprintSet,
    PEInfo,
)
from core.domain.intelligence import Evidence, EvidenceSource, IntelligenceReport
from core.domain.ioc import IocCollection


@dataclass(frozen=True, slots=True)
class AnalyzedArtifact:
    """The immutable, byte-free view of an artifact under analysis.

    Bytes are intentionally absent: providers receive only derived, safe-to-hold
    facts (type, fingerprints, entropy, extracted strings and indicators), so no
    layer beyond the initial ingestion holds raw sample bytes.
    """

    filename: str
    size: int
    fingerprints: FingerprintSet
    file_type: FileType
    metadata: FileMetadata
    entropy: EntropyProfile
    indicators: IocCollection
    text_preview: str = ""
    archive_entries: tuple[ArchiveEntry, ...] = ()
    pe_info: PEInfo | None = None


class IArtifactEvidenceProvider(ABC):
    """Contributes one source of evidence about an analyzed artifact."""

    @property
    @abstractmethod
    def source(self) -> EvidenceSource:
        """The evidence source this provider represents."""

    @abstractmethod
    def assess(self, artifact: AnalyzedArtifact) -> Evidence:
        """Return evidence for ``artifact`` from this source."""


class IFileAnalyzer(ABC):
    """Combines multi-source evidence about an artifact into a report."""

    @abstractmethod
    def analyze(
        self, artifact: AnalyzedArtifact, *, extra_evidence: tuple[Evidence, ...] = ()
    ) -> IntelligenceReport:
        """Analyze ``artifact`` and return a combined intelligence report.

        Args:
            artifact: The byte-free analyzed artifact.
            extra_evidence: Additional evidence gathered by the caller (for
                example, embedded-URL analysis or prior threat intelligence).
        """


class IArchiveInspector(ABC):
    """Inspects archive contents without extracting to disk.

    The extension seam for deep archive analysis: an implementation returns
    evidence about the entries of an archive artifact. Future inspectors (nested
    archives, deeper OOXML inspection) implement this contract.
    """

    @abstractmethod
    def inspect(self, filename: str, data: bytes) -> Evidence:
        """Return evidence about the archive in ``data``."""

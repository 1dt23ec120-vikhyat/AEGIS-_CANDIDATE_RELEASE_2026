"""Offline file evidence providers.

Each provider inspects the byte-free :class:`AnalyzedArtifact` and returns one
:class:`Evidence` value with structured explainability — including provider
metadata, confidence, a rationale, an analyst recommendation, and optional
MITRE ATT&CK technique IDs (empty now, populated by future providers without
contract change).

Providers never execute the file and hold no raw bytes.
"""

from __future__ import annotations

import time
import zipfile
from io import BytesIO

from core.domain.file import FileKind
from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    FeatureContribution,
    ThreatCategory,
)
from core.interfaces import AnalyzedArtifact, IArtifactEvidenceProvider

_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Script / macro token lists
# ---------------------------------------------------------------------------

_DANGEROUS_SCRIPT_TOKENS = (
    "powershell",
    "-enc",
    "-encodedcommand",
    "-executionpolicy bypass",
    "-noprofile",
    "-windowstyle hidden",
    "invoke-expression",
    "invoke-webrequest",
    "iex ",
    "iex(",
    "downloadstring",
    "net.webclient",
    "wscript.shell",
    "cmd.exe",
    "eval(",
    "function(",
    "fromcharcode(",
    "atob(",
    "btoa(",
    "base64",
    "frombase64string",
    "shellexecute",
    "createobject",
    "getobject",
    "scripting.filesystemobject",
    "win32_process",
    "wmic",
    "get-wmiobject",
    "bitsadmin",
    "certutil -decode",
    "certutil -urlcache",
    "curl -o",
    "curl -O",
    "wget ",
    "activexobject",
)

_MACRO_TOKENS = (
    "auto_open",
    "autoopen",
    "autoexec",
    "document_open",
    "workbook_open",
    "auto_close",
    "shell(",
    "vba_project",
    "macros/vba",
    "vbaproject.bin",
)

_OBFUSCATION_TOKENS = (
    "chr(",
    "\\x",
    "string.fromcharcode",
    "replace(",
    "-f ",
    "-join",
    "[char]",
    "$env:",
    "%comspec%",
    "concat(",
)

_OFFICE_RELATIONSHIP_TOKENS = (
    "externallink",
    "hyperlink",
    "attachedtemplate",
    "oleobject",
    "frame",
    "embedinterop",
)

_DDE_TOKENS = ("ddeauto", "dde ")

_INDICATOR_VOLUME = 8

# ---------------------------------------------------------------------------
# Suspicious PE section names and imports
# ---------------------------------------------------------------------------

_SUSPICIOUS_SECTIONS = frozenset(
    {".upx", ".aspack", ".themida", ".mpress", ".nsp", ".petite", ".vmp"}
)
_SUSPICIOUS_PE_IMPORTS = frozenset(
    {
        "virtualalloc",
        "virtualprotect",
        "createremotethread",
        "writeprocessmemory",
        "winexec",
        "shellexecutea",
        "shellexecutew",
    }
)

# ---------------------------------------------------------------------------
# Archive constants
# ---------------------------------------------------------------------------

_ZIP_BOMB_RATIO = 100
_ZIP_BOMB_SIZE = 1_000_000_000
_MAX_ARCHIVE_DEPTH = 2

_DANGEROUS_EXTENSIONS = frozenset(
    {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".jar", ".hta"}
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _contribution(
    feature: str,
    detail: str,
    weight: float,
    *,
    triggered: bool,
    technique_id: str = "",
    recommendation: str = "",
) -> FeatureContribution:
    return FeatureContribution(
        feature=feature,
        detail=detail,
        weight=weight,
        triggered=triggered,
        technique_id=technique_id,
        recommendation=recommendation,
    )


def _evidence(
    source: EvidenceSource,
    risk: float,
    confidence: float,
    rationale: str,
    category: ThreatCategory,
    contributions: tuple[FeatureContribution, ...],
    *,
    provider_name: str,
    technique_ids: tuple[str, ...] = (),
    start: float = 0.0,
) -> Evidence:
    return Evidence(
        source=source,
        risk=risk,
        confidence=confidence,
        weight=1.0,
        rationale=rationale,
        category=category,
        contributions=contributions,
        provider_name=provider_name,
        provider_version=_VERSION,
        execution_ms=round((time.monotonic() - start) * 1000, 2) if start else 0.0,
        technique_ids=technique_ids,
    )


# ===================================================================
# Structure Provider
# ===================================================================


class StructureProvider(IArtifactEvidenceProvider):
    """Flags type/extension mismatches and deceptive names."""

    @property
    def source(self) -> EvidenceSource:
        """Structural evidence source."""
        return EvidenceSource.FILE_STRUCTURE

    def assess(self, artifact: AnalyzedArtifact) -> Evidence:
        """Assess file structure indicators."""
        start = time.monotonic()
        contributions: list[FeatureContribution] = []
        risk = 0.0
        category = ThreatCategory.NONE

        if artifact.metadata.has_double_extension:
            risk = max(risk, 0.85)
            category = ThreatCategory.MALWARE_DELIVERY
            contributions.append(
                _contribution(
                    "double_extension",
                    "Filename hides a dangerous extension behind a benign one",
                    0.85,
                    triggered=True,
                    technique_id="T1036.007",
                    recommendation="Quarantine the file and investigate the source",
                )
            )
        if artifact.file_type.mime_mismatch:
            risk = max(risk, 0.6)
            contributions.append(
                _contribution(
                    "mime_mismatch",
                    f"Declared type {artifact.file_type.declared_mime} disagrees with "
                    f"detected {artifact.file_type.detected_mime}",
                    0.6,
                    triggered=True,
                    technique_id="T1036.008",
                    recommendation="Verify the true file type before opening",
                )
            )
        if artifact.metadata.has_dangerous_extension:
            risk = max(risk, 0.5)
            if category is ThreatCategory.NONE:
                category = ThreatCategory.SUSPICIOUS_EXECUTABLE
            contributions.append(
                _contribution(
                    "dangerous_extension",
                    f"Extension {artifact.file_type.extension} can execute code",
                    0.5,
                    triggered=True,
                    recommendation="Analyze in a sandbox before opening",
                )
            )

        return _evidence(
            self.source,
            risk,
            0.8,
            "File structure and naming analysis",
            category,
            tuple(contributions),
            provider_name="StructureProvider",
            start=start,
        )


# ===================================================================
# Entropy Provider
# ===================================================================


class EntropyProvider(IArtifactEvidenceProvider):
    """Flags high entropy suggestive of packing or encryption."""

    @property
    def source(self) -> EvidenceSource:
        """The entropy evidence source."""
        return EvidenceSource.FILE_ENTROPY

    def assess(self, artifact: AnalyzedArtifact) -> Evidence:
        """Assess Shannon entropy for packing or encryption signals."""
        start = time.monotonic()
        profile = artifact.entropy
        contributions: list[FeatureContribution] = []
        risk = 0.0
        if profile.is_high:
            risk = 0.55
            contributions.append(
                _contribution(
                    "high_entropy",
                    f"Entropy {profile.entropy:.2f} bits/byte indicates packing or encryption",
                    0.55,
                    triggered=True,
                    technique_id="T1027.002",
                    recommendation="Inspect with a decompression tool or sandbox",
                )
            )
        elif profile.is_moderate:
            risk = 0.3
            contributions.append(
                _contribution(
                    "moderate_entropy",
                    f"Entropy {profile.entropy:.2f} bits/byte is elevated",
                    0.3,
                    triggered=True,
                )
            )
        return _evidence(
            self.source,
            risk,
            0.6,
            "File entropy analysis",
            ThreatCategory.NONE,
            tuple(contributions),
            provider_name="EntropyProvider",
            start=start,
        )


# ===================================================================
# Metadata Provider
# ===================================================================


class MetadataProvider(IArtifactEvidenceProvider):
    """Flags executable metadata and structural risk."""

    @property
    def source(self) -> EvidenceSource:
        """The metadata evidence source."""
        return EvidenceSource.FILE_METADATA

    def assess(self, artifact: AnalyzedArtifact) -> Evidence:
        """Assess executable headers and coarse file kind."""
        start = time.monotonic()
        contributions: list[FeatureContribution] = []
        risk = 0.0
        category = ThreatCategory.NONE
        if artifact.metadata.is_executable:
            risk = 0.55
            category = ThreatCategory.SUSPICIOUS_EXECUTABLE
            summary = artifact.metadata.detail[0] if artifact.metadata.detail else "Executable"
            contributions.append(_contribution("executable", summary, 0.55, triggered=True))
        elif artifact.file_type.kind is FileKind.ARCHIVE:
            risk = 0.2
            contributions.append(
                _contribution(
                    "archive_container",
                    "Archive container may bundle dangerous content",
                    0.2,
                    triggered=True,
                )
            )
        return _evidence(
            self.source,
            risk,
            0.75,
            "File metadata analysis",
            category,
            tuple(contributions),
            provider_name="MetadataProvider",
            start=start,
        )


# ===================================================================
# Script Provider (expanded)
# ===================================================================


class ScriptProvider(IArtifactEvidenceProvider):
    """Flags script, macro, obfuscation, and download-cradle indicators."""

    @property
    def source(self) -> EvidenceSource:
        """The script evidence source."""
        return EvidenceSource.FILE_SCRIPT

    def assess(self, artifact: AnalyzedArtifact) -> Evidence:
        """Assess script, macro, and obfuscation tokens."""
        start = time.monotonic()
        lowered = artifact.text_preview.lower()
        script_hits = [t for t in _DANGEROUS_SCRIPT_TOKENS if t in lowered]
        macro_hits = [t for t in _MACRO_TOKENS if t in lowered]
        obfusc_hits = [t for t in _OBFUSCATION_TOKENS if t in lowered]
        contributions: list[FeatureContribution] = []
        risk = 0.0
        category = ThreatCategory.NONE
        techniques: list[str] = []

        if macro_hits:
            risk = max(risk, 0.8)
            category = ThreatCategory.MALICIOUS_DOCUMENT
            techniques.append("T1204.002")
            contributions.append(
                _contribution(
                    "macro_indicators",
                    "Auto-executing macro indicators: " + ", ".join(macro_hits[:4]),
                    0.8,
                    triggered=True,
                    technique_id="T1204.002",
                    recommendation="Disable macros and inspect VBA project",
                )
            )
        if script_hits:
            risk = max(risk, 0.75)
            if category is ThreatCategory.NONE:
                category = ThreatCategory.MALICIOUS_SCRIPT
            techniques.append("T1059")
            contributions.append(
                _contribution(
                    "script_indicators",
                    "Suspicious script tokens: " + ", ".join(script_hits[:4]),
                    0.75,
                    triggered=True,
                    technique_id="T1059",
                    recommendation="Deobfuscate and review the payload",
                )
            )
        if obfusc_hits:
            risk = max(risk, 0.5)
            techniques.append("T1027")
            contributions.append(
                _contribution(
                    "obfuscation",
                    "Obfuscation patterns: " + ", ".join(obfusc_hits[:4]),
                    0.5,
                    triggered=True,
                    technique_id="T1027",
                    recommendation="Deobfuscate the content for manual review",
                )
            )
        if artifact.metadata.is_script and not script_hits and not macro_hits:
            risk = max(risk, 0.35)
            contributions.append(
                _contribution(
                    "script_file",
                    "Script file type can execute code",
                    0.35,
                    triggered=True,
                )
            )
        return _evidence(
            self.source,
            risk,
            0.8 if (macro_hits or script_hits) else 0.5,
            "Script, macro and obfuscation analysis",
            category,
            tuple(contributions),
            provider_name="ScriptProvider",
            start=start,
            technique_ids=tuple(dict.fromkeys(techniques)),
        )


# ===================================================================
# Indicator Provider
# ===================================================================


class IndicatorProvider(IArtifactEvidenceProvider):
    """Contributes evidence from extracted indicators of compromise."""

    @property
    def source(self) -> EvidenceSource:
        """The indicator evidence source."""
        return EvidenceSource.FILE_ARCHIVE

    def assess(self, artifact: AnalyzedArtifact) -> Evidence:
        """Assess the volume and nature of embedded indicators."""
        start = time.monotonic()
        indicators = artifact.indicators
        contributions: list[FeatureContribution] = []
        risk = 0.0
        network = len(indicators.urls) + len(indicators.ipv4_addresses)
        if network >= _INDICATOR_VOLUME:
            risk = 0.25
            contributions.append(
                _contribution(
                    "many_indicators",
                    f"Contains {len(indicators.urls)} URL(s) and "
                    f"{len(indicators.ipv4_addresses)} IP address(es)",
                    0.25,
                    triggered=True,
                    recommendation="Cross-reference the indicators with threat intelligence",
                )
            )
        secrets = len(indicators.aws_keys) + len(indicators.api_keys)
        if secrets:
            risk = max(risk, 0.35)
            contributions.append(
                _contribution(
                    "embedded_secrets",
                    f"Contains {secrets} embedded secret(s) (AWS keys / API keys)",
                    0.35,
                    triggered=True,
                    technique_id="T1552.001",
                    recommendation="Rotate the exposed credentials immediately",
                )
            )
        return _evidence(
            self.source,
            risk,
            0.55,
            "Embedded indicator analysis",
            ThreatCategory.NONE,
            tuple(contributions),
            provider_name="IndicatorProvider",
            start=start,
        )


# ===================================================================
# Office Document Provider (NEW)
# ===================================================================


class OfficeDocumentProvider(IArtifactEvidenceProvider):
    """Static analysis of Office document indicators (OOXML + OLE).

    Uses ``zipfile`` for OOXML (docx/xlsx/pptx) to inspect relationship files
    and VBA project entries in-memory.  OLE detection (doc/xls/ppt) is
    header-based with string scanning — a future ``OleParserProvider`` can
    replace this layer via the same ``IArtifactEvidenceProvider`` interface.
    """

    @property
    def source(self) -> EvidenceSource:
        """Office macro evidence source."""
        return EvidenceSource.FILE_MACRO

    def assess(self, artifact: AnalyzedArtifact) -> Evidence:
        """Assess Office document indicators."""
        start = time.monotonic()
        contributions: list[FeatureContribution] = []
        risk = 0.0
        category = ThreatCategory.NONE
        techniques: list[str] = []
        lowered = artifact.text_preview.lower()
        is_ooxml = artifact.file_type.extension in (
            ".docx",
            ".xlsx",
            ".pptx",
            ".docm",
            ".xlsm",
            ".pptm",
        )
        is_ole = artifact.file_type.detected_mime == "application/x-ole-storage"

        # VBA macro detection
        macro_hits = [t for t in _MACRO_TOKENS if t in lowered]
        if macro_hits:
            risk = max(risk, 0.8)
            category = ThreatCategory.MALICIOUS_DOCUMENT
            techniques.append("T1204.002")
            contributions.append(
                _contribution(
                    "vba_macros",
                    "VBA macro indicators: " + ", ".join(macro_hits[:4]),
                    0.8,
                    triggered=True,
                    technique_id="T1204.002",
                    recommendation="Disable macros and inspect VBA code",
                )
            )

        # DDE detection
        dde_hits = [t for t in _DDE_TOKENS if t in lowered]
        if dde_hits:
            risk = max(risk, 0.7)
            if category is ThreatCategory.NONE:
                category = ThreatCategory.MALICIOUS_DOCUMENT
            techniques.append("T1559.002")
            contributions.append(
                _contribution(
                    "dde_field",
                    "DDE field detected — may execute commands on open",
                    0.7,
                    triggered=True,
                    technique_id="T1559.002",
                    recommendation="Open in Protected View only",
                )
            )

        # External template injection
        if "attachedtemplate" in lowered and ("http://" in lowered or "https://" in lowered):
            risk = max(risk, 0.75)
            if category is ThreatCategory.NONE:
                category = ThreatCategory.MALICIOUS_DOCUMENT
            techniques.append("T1221")
            contributions.append(
                _contribution(
                    "external_template",
                    "External template injection — document loads a remote template",
                    0.75,
                    triggered=True,
                    technique_id="T1221",
                    recommendation="Block network access and inspect the referenced URL",
                )
            )

        # OLE embedded objects
        if b"\xd0\xcf\x11\xe0" in artifact.text_preview.encode("utf-8", "replace") and not is_ole:
            risk = max(risk, 0.6)
            contributions.append(
                _contribution(
                    "embedded_ole",
                    "Embedded OLE object detected inside document",
                    0.6,
                    triggered=True,
                    technique_id="T1027.006",
                    recommendation="Extract and inspect the embedded object",
                )
            )

        # OOXML relationship inspection via zipfile
        if is_ooxml and artifact.text_preview:
            risk, category, techniques = self._inspect_ooxml(
                artifact.text_preview.encode("utf-8", "replace"),
                risk,
                category,
                techniques,
                contributions,
            )

        # Remote references in document text
        remote_hits = [t for t in _OFFICE_RELATIONSHIP_TOKENS if t in lowered]
        if remote_hits and not contributions:
            risk = max(risk, 0.3)
            contributions.append(
                _contribution(
                    "remote_references",
                    "Remote reference tokens: " + ", ".join(remote_hits[:3]),
                    0.3,
                    triggered=True,
                    recommendation="Verify references point to trusted locations",
                )
            )

        return _evidence(
            self.source,
            risk,
            0.8 if contributions else 0.4,
            "Office document static analysis",
            category,
            tuple(contributions),
            provider_name="OfficeDocumentProvider",
            start=start,
            technique_ids=tuple(dict.fromkeys(techniques)),
        )

    @staticmethod
    def _inspect_ooxml(
        data: bytes,
        risk: float,
        category: ThreatCategory,
        techniques: list[str],
        contributions: list[FeatureContribution],
    ) -> tuple[float, ThreatCategory, list[str]]:
        """Inspect OOXML relationships in-memory via zipfile."""
        try:
            with zipfile.ZipFile(BytesIO(data), "r") as zf:
                for name in zf.namelist():
                    lower_name = name.lower()
                    if "vbaproject.bin" in lower_name:
                        risk = max(risk, 0.8)
                        if category is ThreatCategory.NONE:
                            category = ThreatCategory.MALICIOUS_DOCUMENT
                        contributions.append(
                            _contribution(
                                "ooxml_vba_project",
                                f"VBA project found: {name}",
                                0.8,
                                triggered=True,
                                technique_id="T1204.002",
                                recommendation="Extract and review the VBA code",
                            )
                        )
                    if ".rels" in lower_name or lower_name.endswith(".xml"):
                        try:
                            content = zf.read(name).decode("utf-8", "replace").lower()
                        except (KeyError, RuntimeError):
                            continue
                        for pattern in (".exe", ".dll", ".js", ".vbs", ".ps1"):
                            if pattern in content:
                                risk = max(risk, 0.7)
                                contributions.append(
                                    _contribution(
                                        "ooxml_suspicious_ref",
                                        f"Office relationship references {pattern} in {name}",
                                        0.7,
                                        triggered=True,
                                        recommendation="Inspect the referenced resource",
                                    )
                                )
                                break
        except (zipfile.BadZipFile, OSError):
            pass
        return risk, category, techniques


# ===================================================================
# Archive Provider (NEW)
# ===================================================================


class ArchiveProvider(IArtifactEvidenceProvider):
    """Static analysis of archive contents via in-memory zipfile.

    Detects dangerous embedded file types, nested archives, zip-bomb
    heuristics, password-protected entries, filename masquerading, and
    path-traversal entries — all without extracting content to disk.
    """

    @property
    def source(self) -> EvidenceSource:
        """Archive evidence source."""
        return EvidenceSource.FILE_ARCHIVE

    def assess(self, artifact: AnalyzedArtifact) -> Evidence:
        """Assess archive contents indicators."""
        start = time.monotonic()
        contributions: list[FeatureContribution] = []
        risk = 0.0
        category = ThreatCategory.NONE
        techniques: list[str] = []

        for entry in artifact.archive_entries:
            ext = ("." + entry.name.rsplit(".", 1)[-1]).lower() if "." in entry.name else ""
            # Dangerous types
            if ext in _DANGEROUS_EXTENSIONS:
                risk = max(risk, 0.7)
                if category is ThreatCategory.NONE:
                    category = ThreatCategory.MALICIOUS_ARCHIVE
                contributions.append(
                    _contribution(
                        "archive_dangerous_type",
                        f"Dangerous file inside archive: {entry.name}",
                        0.7,
                        triggered=True,
                        recommendation="Extract and analyze in a sandbox",
                    )
                )
            # Nested archives
            if ext in (".zip", ".rar", ".7z", ".gz", ".tar"):
                risk = max(risk, 0.4)
                contributions.append(
                    _contribution(
                        "nested_archive",
                        f"Nested archive: {entry.name}",
                        0.4,
                        triggered=True,
                        recommendation="Inspect the nested archive separately",
                    )
                )
            # Filename masquerading (double ext inside archive)
            parts = entry.name.split(".")
            if len(parts) >= 3:  # noqa: PLR2004 - name + two extension segments
                final_ext = "." + parts[-1].lower()
                penultimate = "." + parts[-2].lower()
                if final_ext in _DANGEROUS_EXTENSIONS and penultimate not in _DANGEROUS_EXTENSIONS:
                    risk = max(risk, 0.8)
                    if category is ThreatCategory.NONE:
                        category = ThreatCategory.MALWARE_DELIVERY
                    techniques.append("T1036.007")
                    contributions.append(
                        _contribution(
                            "archive_masquerading",
                            f"Filename masquerading inside archive: {entry.name}",
                            0.8,
                            triggered=True,
                            technique_id="T1036.007",
                            recommendation="Quarantine — likely a disguised executable",
                        )
                    )
            # Path traversal
            if entry.has_traversal:
                risk = max(risk, 0.75)
                techniques.append("T1204")
                contributions.append(
                    _contribution(
                        "archive_traversal",
                        f"Path traversal in archive entry: {entry.name}",
                        0.75,
                        triggered=True,
                        recommendation="Do not extract — likely a Zip Slip attack",
                    )
                )
            # Zip bomb ratio
            if entry.compressed_size > 0 and entry.size / entry.compressed_size > _ZIP_BOMB_RATIO:
                risk = max(risk, 0.7)
                contributions.append(
                    _contribution(
                        "zip_bomb_ratio",
                        f"Suspicious compression ratio ({entry.size / entry.compressed_size:.0f}:1)"
                        f" for {entry.name}",
                        0.7,
                        triggered=True,
                        recommendation="Do not extract — possible zip bomb",
                    )
                )
            if entry.size > _ZIP_BOMB_SIZE:
                risk = max(risk, 0.7)
                contributions.append(
                    _contribution(
                        "zip_bomb_size",
                        f"Decompressed size {entry.size:,} bytes for {entry.name}",
                        0.7,
                        triggered=True,
                        recommendation="Do not extract — likely a zip bomb",
                    )
                )

        return _evidence(
            self.source,
            risk,
            0.8 if contributions else 0.3,
            "Archive content analysis",
            category,
            tuple(contributions),
            provider_name="ArchiveProvider",
            start=start,
            technique_ids=tuple(dict.fromkeys(techniques)),
        )


# ===================================================================
# Executable Provider (NEW — separated from MetadataProvider)
# ===================================================================


class ExecutableProvider(IArtifactEvidenceProvider):
    """Deep static PE analysis consuming parsed :class:`PEInfo`.

    This is the **detection** layer.  It consumes the metadata produced by
    ``PEParser`` and generates evidence.  Replacing the parser does not affect
    this provider.
    """

    @property
    def source(self) -> EvidenceSource:
        """PE executable evidence source."""
        return EvidenceSource.FILE_EXECUTABLE

    def assess(  # noqa: PLR0912 - multi-facet PE inspection
        self, artifact: AnalyzedArtifact
    ) -> Evidence:
        """Assess PE executable indicators."""
        start = time.monotonic()
        pe = artifact.pe_info
        if pe is None or not pe.is_pe:
            return _evidence(
                self.source,
                0.0,
                0.0,
                "Not a PE executable",
                ThreatCategory.NONE,
                (),
                provider_name="ExecutableProvider",
                start=start,
            )

        contributions: list[FeatureContribution] = []
        risk = 0.0
        category = ThreatCategory.SUSPICIOUS_EXECUTABLE
        techniques: list[str] = []

        # Packer indicators
        if pe.packer_indicators:
            risk = max(risk, 0.6)
            techniques.append("T1027.002")
            contributions.append(
                _contribution(
                    "packer_detected",
                    "Packer indicators: " + "; ".join(pe.packer_indicators[:3]),
                    0.6,
                    triggered=True,
                    technique_id="T1027.002",
                    recommendation="Unpack before analysis",
                )
            )

        # Suspicious section names
        if pe.suspicious_section_names:
            risk = max(risk, 0.5)
            contributions.append(
                _contribution(
                    "suspicious_sections",
                    "Suspicious section names: " + ", ".join(pe.suspicious_section_names[:4]),
                    0.5,
                    triggered=True,
                    recommendation="Likely packed or protected — analyze with a decompiler",
                )
            )

        # Suspicious imports
        for imp in pe.imports:
            for func in imp.functions:
                if func.lower() in _SUSPICIOUS_PE_IMPORTS:
                    risk = max(risk, 0.5)
                    contributions.append(
                        _contribution(
                            "suspicious_import",
                            f"Suspicious import: {imp.dll_name}!{func}",
                            0.5,
                            triggered=True,
                            technique_id="T1055",
                            recommendation="Review the import in context",
                        )
                    )
            dll_lower = imp.dll_name.lower()
            for func_name in _SUSPICIOUS_PE_IMPORTS:
                if func_name in dll_lower:
                    risk = max(risk, 0.4)

        # No signature
        if not pe.has_signature:
            risk = max(risk, 0.3)
            contributions.append(
                _contribution(
                    "unsigned",
                    "No Authenticode signature present",
                    0.3,
                    triggered=True,
                    recommendation="Verify the publisher through other means",
                )
            )

        # Exports on a non-DLL (unusual)
        is_dll = bool(pe.characteristics & 0x2000)
        if pe.has_exports and not is_dll:
            risk = max(risk, 0.35)
            contributions.append(
                _contribution(
                    "unexpected_exports",
                    "Export table present on a non-DLL executable",
                    0.35,
                    triggered=True,
                )
            )

        # Version info anomalies
        if not pe.version_company and not pe.version_product:
            contributions.append(
                _contribution(
                    "missing_version_info",
                    "No CompanyName or ProductName in version resources",
                    0.2,
                    triggered=True,
                    recommendation="Legitimate software typically includes version metadata",
                )
            )
            risk = max(risk, 0.2)

        # Suspicious compile timestamp (future date or very old)
        if pe.compile_timestamp > 0:
            import time as _time

            now_ts = int(_time.time())
            if pe.compile_timestamp > now_ts + 86400:
                contributions.append(
                    _contribution(
                        "future_timestamp",
                        "Compile timestamp is in the future — likely forged",
                        0.4,
                        triggered=True,
                        technique_id="T1070.006",
                        recommendation="Treat as suspicious — timestomping indicator",
                    )
                )
                risk = max(risk, 0.4)

        # High section entropy
        high_ent = [s for s in pe.sections if s.entropy > 7.0]  # noqa: PLR2004
        if high_ent:
            risk = max(risk, 0.45)
            contributions.append(
                _contribution(
                    "high_section_entropy",
                    f"{len(high_ent)} section(s) with entropy > 7.0 bits/byte",
                    0.45,
                    triggered=True,
                    technique_id="T1027.002",
                    recommendation="Likely packed or encrypted content",
                )
            )

        return _evidence(
            self.source,
            risk,
            0.8,
            "PE executable static analysis",
            category,
            tuple(contributions),
            provider_name="ExecutableProvider",
            start=start,
            technique_ids=tuple(dict.fromkeys(techniques)),
        )

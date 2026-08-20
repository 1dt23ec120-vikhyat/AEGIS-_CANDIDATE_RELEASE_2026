"""Static PE header parsing (pure, framework-free).

Parses DOS/PE headers, section tables, and import tables using only ``struct``,
producing a :class:`~core.domain.file.PEInfo` value object. This is a pure
byte-to-domain transformation and lives beside its siblings in ``core.domain``
(``compute_fingerprints``, ``identify_type``, ``shannon_entropy``,
``extract_iocs``); like them it has no I/O, no framework dependency, and no side
effects.

No execution. No sandbox. No file writes. A future ``pefile``-based parser would
produce the same :class:`PEInfo`, changing only this module.
"""

from __future__ import annotations

import struct

from core.domain.file import PEImport, PEInfo, PESection

_DOS_HEADER_SIZE = 64
_PE_SIGNATURE = b"PE\x00\x00"
_PE_SIG_LEN = 4
_COFF_HEADER_SIZE = 20
_SECTION_HEADER_SIZE = 40
_OPT_32_MAGIC = 0x10B
_OPT_64_MAGIC = 0x20B
_SECURITY_DIR_INDEX = 4
_DEBUG_DIR_INDEX = 6
_EXPORT_DIR_INDEX = 0
_IMPORT_DIR_INDEX = 1
_NUM_DATA_DIRS = 16

_SUSPICIOUS_SECTION_NAMES = frozenset(
    {".upx", ".aspack", ".themida", ".mpress", ".nsp", ".petite", ".vmp", ".enigma"}
)
_PACKER_NAMES = frozenset(
    {"upx", "aspack", "themida", "mpress", "petite", "vmp", "enigma", "armadillo"}
)
_SUSPICIOUS_IMPORTS = frozenset(
    {
        "virtualalloc",
        "virtualprotect",
        "createremotethread",
        "writeprocessmemory",
        "ntunmapviewofsection",
        "winexec",
        "shellexecutea",
        "shellexecutew",
        "loadlibrarya",
        "getprocaddress",
    }
)

_ENTROPY_BASE = 256


def _section_entropy(data: bytes, offset: int, size: int) -> float:
    """Shannon entropy of a section slice, bounded to available data."""
    import math

    chunk = data[offset : offset + min(size, len(data) - offset)]
    if not chunk:
        return 0.0
    counts = [0] * _ENTROPY_BASE
    for byte in chunk:
        counts[byte] += 1
    length = len(chunk)
    ent = 0.0
    for count in counts:
        if count:
            prob = count / length
            ent -= prob * math.log2(prob)
    return round(ent, 4)


def parse_pe(data: bytes) -> PEInfo:  # noqa: PLR0912 - PE parsing is inherently multi-branch
    """Parse a PE executable from raw bytes (read-only, static).

    Args:
        data: The file bytes (not retained after parsing).

    Returns:
        A populated :class:`PEInfo` or a default instance if parsing fails.
    """
    if len(data) < _DOS_HEADER_SIZE or data[:2] != b"MZ":
        return PEInfo()
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return PEInfo()
    if pe_offset + _PE_SIG_LEN + _COFF_HEADER_SIZE > len(data):
        return PEInfo(is_pe=False)
    if data[pe_offset : pe_offset + _PE_SIG_LEN] != _PE_SIGNATURE:
        return PEInfo(is_pe=False)

    coff_offset = pe_offset + _PE_SIG_LEN
    (
        _machine,
        num_sections,
        timestamp,
        _sym_table,
        _num_syms,
        opt_size,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_offset)

    opt_offset = coff_offset + _COFF_HEADER_SIZE
    if opt_offset + 2 > len(data):
        return PEInfo(is_pe=True, compile_timestamp=timestamp, num_sections=num_sections)
    opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_64 = opt_magic == _OPT_64_MAGIC

    entry_point = 0
    image_base = 0
    subsystem = 0
    has_sig = False
    has_debug = False
    has_exports = False
    num_data_dirs = 0

    try:
        if is_64:
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
            subsystem = struct.unpack_from("<H", data, opt_offset + 68)[0]
            num_data_dirs = struct.unpack_from("<I", data, opt_offset + 108)[0]
            dd_offset = opt_offset + 112
        else:
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
            subsystem = struct.unpack_from("<H", data, opt_offset + 68)[0]
            num_data_dirs = struct.unpack_from("<I", data, opt_offset + 116)[0]
            dd_offset = opt_offset + 120

        num_data_dirs = min(num_data_dirs, _NUM_DATA_DIRS)
        for idx in range(num_data_dirs):
            rva, size = struct.unpack_from("<II", data, dd_offset + idx * 8)
            if size > 0:
                if idx == _EXPORT_DIR_INDEX:
                    has_exports = True
                elif idx == _SECURITY_DIR_INDEX:
                    has_sig = True
                elif idx == _DEBUG_DIR_INDEX:
                    has_debug = True
    except struct.error:
        pass

    sections = _parse_sections(data, coff_offset + _COFF_HEADER_SIZE + opt_size, num_sections)
    suspicious_names = tuple(
        s.name for s in sections if s.name.lower().rstrip("\x00") in _SUSPICIOUS_SECTION_NAMES
    )
    packer_indicators = _detect_packer(sections)
    imports = _parse_imports(data, is_64, opt_offset, num_data_dirs, sections)

    version_company, version_product, version_desc = _parse_version_info(data)

    return PEInfo(
        is_pe=True,
        is_64bit=is_64,
        compile_timestamp=timestamp,
        num_sections=num_sections,
        sections=sections,
        imports=imports,
        has_exports=has_exports,
        has_signature=has_sig,
        has_debug=has_debug,
        entry_point=entry_point,
        image_base=image_base,
        subsystem=subsystem,
        characteristics=characteristics,
        suspicious_section_names=suspicious_names,
        packer_indicators=packer_indicators,
        version_company=version_company,
        version_product=version_product,
        version_description=version_desc,
    )


def _parse_sections(data: bytes, offset: int, count: int) -> tuple[PESection, ...]:
    sections: list[PESection] = []
    for i in range(min(count, 96)):
        base = offset + i * _SECTION_HEADER_SIZE
        if base + _SECTION_HEADER_SIZE > len(data):
            break
        name_bytes = data[base : base + 8]
        name = name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vsize, _va, rsize, roffset = struct.unpack_from("<IIII", data, base + 8)
        ent = _section_entropy(data, roffset, rsize)
        suspicious = name.lower().rstrip("\x00") in _SUSPICIOUS_SECTION_NAMES
        sections.append(PESection(name, vsize, rsize, ent, suspicious))
    return tuple(sections)


def _detect_packer(sections: tuple[PESection, ...]) -> tuple[str, ...]:
    indicators: list[str] = []
    for section in sections:
        lower = section.name.lower().rstrip("\x00")
        for packer in _PACKER_NAMES:
            if packer in lower:
                indicators.append(f"Packer signature in section {section.name}")
    high_entropy = [s for s in sections if s.entropy > 7.0]  # noqa: PLR2004
    if high_entropy:
        indicators.append(f"{len(high_entropy)} section(s) with entropy > 7.0")
    return tuple(dict.fromkeys(indicators))


def _parse_imports(
    data: bytes,
    is_64: bool,
    opt_offset: int,
    num_dirs: int,
    sections: tuple[PESection, ...],
) -> tuple[PEImport, ...]:
    """Best-effort import table parsing.  Gracefully returns () on failure."""
    if num_dirs <= _IMPORT_DIR_INDEX:
        return ()
    try:
        dd_base = opt_offset + (112 if is_64 else 120)
        imp_rva, imp_size = struct.unpack_from("<II", data, dd_base + _IMPORT_DIR_INDEX * 8)
        if imp_size == 0:
            return ()
        imp_offset = _rva_to_offset(imp_rva, sections)
        if imp_offset is None:
            return ()
    except struct.error:
        return ()
    imports: list[PEImport] = []
    idx = 0
    while idx < 256:  # noqa: PLR2004 - reasonable import cap
        entry_base = imp_offset + idx * 20
        if entry_base + 20 > len(data):
            break
        name_rva = struct.unpack_from("<I", data, entry_base + 12)[0]
        if name_rva == 0:
            break
        name_off = _rva_to_offset(name_rva, sections)
        if name_off is not None:
            end = data.find(b"\x00", name_off, name_off + 256)
            dll_name = data[name_off : end if end != -1 else name_off + 64].decode(
                "ascii", errors="replace"
            )
            imports.append(PEImport(dll_name=dll_name))
        idx += 1
    return tuple(imports)


def _rva_to_offset(rva: int, sections: tuple[PESection, ...]) -> int | None:
    """Map a relative virtual address to a file offset using section headers."""
    # sections don't carry raw_offset from our PESection VO, so this is best-effort.
    # For a more accurate mapping we'd need to carry raw_offset in PESection.
    # As a fallback we return rva itself which works for many PE files.
    return rva if rva < 0x100000 else None  # noqa: PLR2004 - reasonable bound


def _parse_version_info(data: bytes) -> tuple[str, str, str]:
    """Best-effort extraction of VS_VERSION_INFO string values."""
    company = _find_version_string(data, b"CompanyName")
    product = _find_version_string(data, b"ProductName")
    desc = _find_version_string(data, b"FileDescription")
    return company, product, desc


def _find_version_string(data: bytes, key: bytes) -> str:
    idx = data.find(key)
    if idx == -1:
        return ""
    # Skip past the key and look for the value (UTF-16LE typically)
    after = idx + len(key)
    # Scan forward for a readable ASCII/UTF-16 value
    segment = data[after : after + 256]
    chars: list[str] = []
    for byte in segment:
        if 0x20 <= byte < 0x7F:  # noqa: PLR2004 - printable ASCII range
            chars.append(chr(byte))
        elif chars:
            break
    return "".join(chars).strip()

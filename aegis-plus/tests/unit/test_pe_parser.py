"""Tests for the static PE parser."""

from __future__ import annotations

import struct

from ai.file_analysis.pe_parser import parse_pe


def test_non_pe_returns_default() -> None:
    pe = parse_pe(b"not an executable at all")
    assert not pe.is_pe


def test_dos_header_only() -> None:
    data = b"MZ" + b"\x00" * 62
    pe = parse_pe(data)
    # No PE signature at the offset, should return is_pe=False or minimal info
    assert not pe.is_pe or pe.num_sections == 0


def test_valid_pe_parses_sections() -> None:
    # Build a minimal valid PE
    dos = bytearray(b"MZ" + b"\x00" * 62)
    pe_offset = 64
    struct.pack_into("<I", dos, 0x3C, pe_offset)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 1234567890, 0, 0, 0xE0, 0)
    opt = struct.pack("<H", 0x10B) + b"\x00" * (0xE0 - 2)
    section = (
        b".text\x00\x00\x00" + struct.pack("<IIII", 0x1000, 0x1000, 0x200, 0x200) + b"\x00" * 24
    )
    data = bytes(dos) + pe_sig + coff + opt + section + b"\x00" * 1024
    pe = parse_pe(data)
    assert pe.is_pe
    assert pe.num_sections == 1
    assert pe.compile_timestamp == 1234567890
    assert len(pe.sections) == 1
    assert pe.sections[0].name.startswith(".text")

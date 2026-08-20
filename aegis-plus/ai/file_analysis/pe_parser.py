"""PE parser adapter.

The AI-layer adapter that satisfies the Core :class:`IPeParser` port. The actual
parsing is the pure, framework-free :func:`core.domain.pe.parse_pe`; this module
adds the injectable adapter used by the composition root and preserves the
historical ``parse_pe`` import path for backward compatibility.

Replacing the parser (e.g. a ``pefile``-based implementation) means providing a
new :class:`IPeParser` and wiring it in the container — no service change.
"""

from __future__ import annotations

from core.domain.file import PEInfo
from core.domain.pe import parse_pe
from core.interfaces.pe_parser import IPeParser

__all__ = ["StructPeParser", "parse_pe"]


class StructPeParser(IPeParser):
    """``struct``-based static PE parser adapter."""

    def parse(self, data: bytes) -> PEInfo:
        """Parse raw bytes into :class:`PEInfo` via the pure core parser."""
        return parse_pe(data)

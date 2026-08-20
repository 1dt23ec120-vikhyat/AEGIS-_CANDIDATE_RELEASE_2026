"""PE parser port.

Core-owned contract for static PE header parsing. The ingestion service depends
on this abstraction rather than on any concrete parser, so the struct-based
parser that ships today can be swapped for a ``pefile``-based one without
changing service code (Dependency Inversion).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.file import PEInfo


class IPeParser(ABC):
    """Static PE parsing contract."""

    @abstractmethod
    def parse(self, data: bytes) -> PEInfo:
        """Parse raw bytes into :class:`PEInfo` (read-only, static, no execution)."""

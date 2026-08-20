"""Offline file intelligence: hybrid analyzer, evidence providers, and PE parser."""

from ai.file_analysis.hybrid_analyzer import HybridFileAnalyzer
from ai.file_analysis.pe_parser import StructPeParser, parse_pe
from ai.file_analysis.providers import (
    ArchiveProvider,
    EntropyProvider,
    ExecutableProvider,
    IndicatorProvider,
    MetadataProvider,
    OfficeDocumentProvider,
    ScriptProvider,
    StructureProvider,
)

__all__ = [
    "ArchiveProvider",
    "EntropyProvider",
    "ExecutableProvider",
    "HybridFileAnalyzer",
    "IndicatorProvider",
    "MetadataProvider",
    "OfficeDocumentProvider",
    "ScriptProvider",
    "StructPeParser",
    "StructureProvider",
    "parse_pe",
]

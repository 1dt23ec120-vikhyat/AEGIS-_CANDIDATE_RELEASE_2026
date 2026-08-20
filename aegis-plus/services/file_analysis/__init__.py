"""File Analysis vertical: ingestion, analysis, and investigation services."""

from services.file_analysis.ingestion import FileIngestor
from services.file_analysis.investigation import FileInvestigationService
from services.file_analysis.service import (
    EmbeddedUrlResult,
    FileAnalysisService,
    FileScanOutcome,
)

__all__ = [
    "EmbeddedUrlResult",
    "FileAnalysisService",
    "FileIngestor",
    "FileInvestigationService",
    "FileScanOutcome",
]

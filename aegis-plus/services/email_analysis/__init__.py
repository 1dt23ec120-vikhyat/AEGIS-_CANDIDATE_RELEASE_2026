"""Email analysis application service."""

from services.email_analysis.investigation import EmailInvestigationService
from services.email_analysis.service import (
    EmailAnalysisService,
    EmailScanOutcome,
    EmbeddedUrlResult,
)

__all__ = [
    "EmailAnalysisService",
    "EmailInvestigationService",
    "EmailScanOutcome",
    "EmbeddedUrlResult",
]

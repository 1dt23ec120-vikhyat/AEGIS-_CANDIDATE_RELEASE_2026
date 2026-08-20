"""Gmail connector service (M14).

The read-only Gmail input connector that feeds messages into the existing Email
Analysis pipeline. Exposes connection management, manual synchronization, and the
analyst-workspace read-model (message list + per-message detail). It contains no
analysis logic of its own — every intelligence value is projected from the
existing pipeline.
"""

from services.gmail.dtos import (
    GmailEvidenceItem,
    GmailMessageDetail,
    GmailMessageView,
    GmailPreview,
    GmailSourceItem,
    GmailUrlItem,
)
from services.gmail.service import (
    GmailConnectionStatus,
    GmailIngestionService,
    GmailMessageOutcome,
    GmailSyncResult,
    GmailSyncStateContext,
)

__all__ = [
    "GmailConnectionStatus",
    "GmailEvidenceItem",
    "GmailIngestionService",
    "GmailMessageDetail",
    "GmailMessageOutcome",
    "GmailMessageView",
    "GmailPreview",
    "GmailSourceItem",
    "GmailSyncResult",
    "GmailSyncStateContext",
    "GmailUrlItem",
]

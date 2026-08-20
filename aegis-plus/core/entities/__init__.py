"""Enterprise domain entities.

Pure domain models with identity-based equality and shared audit timestamps,
independent of any persistence framework.
"""

from core.entities.audit_log import AuditLog
from core.entities.base import AggregateRoot, BaseEntity
from core.entities.campaign import Campaign
from core.entities.configuration import Configuration
from core.entities.email_investigation import EmailInvestigation
from core.entities.email_scan import EmailScan
from core.entities.file_investigation import FileInvestigation
from core.entities.file_scan import FileScan
from core.entities.incident import Incident, IncidentComment, IncidentEvent
from core.entities.threat_entry import ThreatEntry
from core.entities.url_scan import UrlScan

__all__ = [
    "AggregateRoot",
    "AuditLog",
    "BaseEntity",
    "Campaign",
    "Configuration",
    "EmailInvestigation",
    "EmailScan",
    "FileInvestigation",
    "FileScan",
    "Incident",
    "IncidentComment",
    "IncidentEvent",
    "ThreatEntry",
    "UrlScan",
]

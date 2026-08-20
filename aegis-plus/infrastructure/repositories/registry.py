"""Repository registry.

Maps each Core entity type to a factory that builds its repository bound to a
session. The Unit of Work uses this registry to hand out repositories that share
its transaction. Registering a new entity here is the only step needed to make
it available through the Unit of Work.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

from core.entities import (
    AuditLog,
    Campaign,
    Configuration,
    EmailInvestigation,
    EmailScan,
    FileInvestigation,
    FileScan,
    Incident,
    ThreatEntry,
    UrlScan,
)
from core.entities.base import BaseEntity
from core.interfaces import IRepository
from infrastructure.database import mappers
from infrastructure.database.models import (
    AuditLogRow,
    CampaignRow,
    ConfigurationRow,
    EmailInvestigationRow,
    EmailScanRow,
    FileInvestigationRow,
    FileScanRow,
    IncidentRow,
    UrlScanRow,
)
from infrastructure.repositories.base_repository import SqlAlchemyRepository
from infrastructure.repositories.threat_repository import (
    SqlAlchemyThreatIntelligenceRepository,
)

# A factory takes a session and returns a repository bound to it. The generic
# parameter is erased to ``Any`` here because the registry stores heterogeneous
# repository types keyed by entity type; the Unit of Work re-narrows the type on
# retrieval.
RepositoryFactory = Callable[[Session], IRepository[Any]]


def _audit_log_repository(session: Session) -> IRepository[AuditLog]:
    return SqlAlchemyRepository(
        session,
        row_type=AuditLogRow,
        to_entity=mappers.audit_log_to_entity,
        to_row=mappers.audit_log_to_row,
        apply_updates=mappers.apply_audit_log_updates,
    )


def _configuration_repository(session: Session) -> IRepository[Configuration]:
    return SqlAlchemyRepository(
        session,
        row_type=ConfigurationRow,
        to_entity=mappers.configuration_to_entity,
        to_row=mappers.configuration_to_row,
        apply_updates=mappers.apply_configuration_updates,
    )


def _url_scan_repository(session: Session) -> IRepository[UrlScan]:
    return SqlAlchemyRepository(
        session,
        row_type=UrlScanRow,
        to_entity=mappers.url_scan_to_entity,
        to_row=mappers.url_scan_to_row,
        apply_updates=mappers.apply_url_scan_updates,
    )


def _threat_entry_repository(session: Session) -> IRepository[ThreatEntry]:
    return SqlAlchemyThreatIntelligenceRepository(session)


def _email_scan_repository(session: Session) -> IRepository[EmailScan]:
    return SqlAlchemyRepository(
        session,
        row_type=EmailScanRow,
        to_entity=mappers.email_scan_to_entity,
        to_row=mappers.email_scan_to_row,
        apply_updates=mappers.apply_email_scan_updates,
    )


def _email_investigation_repository(session: Session) -> IRepository[EmailInvestigation]:
    return SqlAlchemyRepository(
        session,
        row_type=EmailInvestigationRow,
        to_entity=mappers.email_investigation_to_entity,
        to_row=mappers.email_investigation_to_row,
        apply_updates=mappers.apply_email_investigation_updates,
    )


def _file_scan_repository(session: Session) -> IRepository[FileScan]:
    return SqlAlchemyRepository(
        session,
        row_type=FileScanRow,
        to_entity=mappers.file_scan_to_entity,
        to_row=mappers.file_scan_to_row,
        apply_updates=mappers.apply_file_scan_updates,
    )


def _file_investigation_repository(session: Session) -> IRepository[FileInvestigation]:
    return SqlAlchemyRepository(
        session,
        row_type=FileInvestigationRow,
        to_entity=mappers.file_investigation_to_entity,
        to_row=mappers.file_investigation_to_row,
        apply_updates=mappers.apply_file_investigation_updates,
    )


def _campaign_repository(session: Session) -> IRepository[Campaign]:
    return SqlAlchemyRepository(
        session,
        row_type=CampaignRow,
        to_entity=mappers.campaign_to_entity,
        to_row=mappers.campaign_to_row,
        apply_updates=mappers.apply_campaign_updates,
    )


def _incident_repository(session: Session) -> IRepository[Incident]:
    return SqlAlchemyRepository(
        session,
        row_type=IncidentRow,
        to_entity=mappers.incident_to_entity,
        to_row=mappers.incident_to_row,
        apply_updates=mappers.apply_incident_updates,
    )


def default_repository_factories() -> dict[type[BaseEntity], RepositoryFactory]:
    """Return the default entity-type to repository-factory registry."""
    return {
        AuditLog: _audit_log_repository,
        Configuration: _configuration_repository,
        UrlScan: _url_scan_repository,
        ThreatEntry: _threat_entry_repository,
        EmailScan: _email_scan_repository,
        EmailInvestigation: _email_investigation_repository,
        FileScan: _file_scan_repository,
        FileInvestigation: _file_investigation_repository,
        Campaign: _campaign_repository,
        Incident: _incident_repository,
    }

"""Incident correlation service.

Turns individual detections into incidents and campaigns. For each malicious
observation it extracts correlatable artifacts, compares them against every open
incident using the pure :func:`correlate` policy, and either folds the detection
into the best-matching incident (updating its campaign) or opens a new incident
and campaign.

The service is artifact-agnostic: it consumes :class:`ArtifactRef` values, so
future observable types (files, IP addresses, processes, cloud resources) can be
correlated by extending :class:`ArtifactKind` and the extractor - the matching
policy, persistence, and workflow need no change.

Analyst workflow state is never modified here; correlation only appends evidence.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from core.constants import AuditOutcome, IncidentStatus, InvestigationPriority
from core.domain.correlation import (
    ArtifactKind,
    ArtifactRef,
    CorrelationLink,
    correlate,
    subject_pattern,
)
from core.domain.email import EmailMessage
from core.domain.intelligence import ThreatCategory
from core.entities import Campaign, EmailScan, Incident
from core.interfaces import IAuditTrail, ILogger, IRepository, IUnitOfWork

_ACTION_CORRELATED = "incident.correlated"
_ACTION_OPENED = "incident.opened"
_MIN_LINK_STRENGTH = 1


@dataclass(frozen=True, slots=True)
class CorrelationOutcome:
    """The result of correlating one detection."""

    incident: Incident
    campaign: Campaign
    link: CorrelationLink
    created_incident: bool
    created_campaign: bool


class IncidentCorrelationService:
    """Correlates detections into incidents and campaigns."""

    def __init__(
        self,
        unit_of_work_factory: Callable[[], IUnitOfWork],
        audit: IAuditTrail,
        logger: ILogger,
    ) -> None:
        """Initialize the service.

        Args:
            unit_of_work_factory: Produces a Unit of Work for persistence.
            audit: The audit trail port.
            logger: Injected logger.
        """
        self._unit_of_work_factory = unit_of_work_factory
        self._audit = audit
        self._logger = logger

    # --- artifact extraction -------------------------------------------

    @staticmethod
    def extract_artifacts(
        email: EmailMessage, scan: EmailScan, urls: tuple[str, ...]
    ) -> tuple[ArtifactRef, ...]:
        """Extract every correlatable observable from an email detection."""
        refs: list[ArtifactRef] = []
        if email.sender.is_present:
            refs.append(ArtifactRef(ArtifactKind.SENDER, email.sender.address))
            if email.sender.domain:
                refs.append(ArtifactRef(ArtifactKind.DOMAIN, email.sender.domain))
        if email.reply_to and email.reply_to.is_present:
            refs.append(ArtifactRef(ArtifactKind.REPLY_TO, email.reply_to.address))
        pattern = subject_pattern(email.subject)
        if pattern:
            refs.append(ArtifactRef(ArtifactKind.SUBJECT_PATTERN, pattern))
        for url in urls:
            refs.append(ArtifactRef(ArtifactKind.URL, url))
            digest = hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()
            refs.append(ArtifactRef(ArtifactKind.URL_HASH, digest))
        for attachment in email.attachments:
            refs.append(ArtifactRef(ArtifactKind.ATTACHMENT_HASH, attachment.sha256))
        if scan.category is not ThreatCategory.NONE:
            refs.append(ArtifactRef(ArtifactKind.CATEGORY, scan.category.value))
        return tuple({ref.key: ref for ref in refs}.values())

    # --- correlation ----------------------------------------------------

    def correlate_email(
        self, email: EmailMessage, scan: EmailScan, urls: tuple[str, ...]
    ) -> CorrelationOutcome:
        """Correlate an email detection into an incident and campaign."""
        artifacts = self.extract_artifacts(email, scan, urls)
        recipients = tuple(address.address for address in email.recipients)
        return self._correlate(
            artifacts=artifacts,
            category=scan.category,
            risk_score=scan.threat_score,
            scan_id=str(scan.id),
            recipients=recipients,
            campaign_name=self._campaign_name(email, scan),
            incident_title=self._incident_title(email, scan),
            opened_detail=(
                f"Opened from detection {scan.verdict.value} "
                f"({scan.category.value}) for {email.sender.address}"
            ),
            subject=email.sender.address,
        )

    def correlate_file(
        self,
        *,
        artifacts: tuple[ArtifactRef, ...],
        category: ThreatCategory,
        risk_score: float,
        scan_id: str,
        filename: str,
        verdict: str,
    ) -> CorrelationOutcome:
        """Correlate a file detection into an incident and campaign.

        Reuses the same matching, incident, and campaign flow as email
        correlation; only the observables and descriptive labels differ.
        """
        label = category.value.replace("_", " ").title()
        return self._correlate(
            artifacts=artifacts,
            category=category,
            risk_score=risk_score,
            scan_id=scan_id,
            recipients=(),
            campaign_name=f"{label}: {filename}",
            incident_title=f"{label} - {filename}",
            opened_detail=f"Opened from file detection {verdict} ({category.value}) for {filename}",
            subject=filename,
        )

    def _correlate(
        self,
        *,
        artifacts: tuple[ArtifactRef, ...],
        category: ThreatCategory,
        risk_score: float,
        scan_id: str,
        recipients: tuple[str, ...],
        campaign_name: str,
        incident_title: str,
        opened_detail: str,
        subject: str,
    ) -> CorrelationOutcome:
        """Shared correlation flow for any detection vertical."""
        with self._unit_of_work_factory() as uow:
            incidents = uow.get_repository(Incident)
            campaigns = uow.get_repository(Campaign)

            match, link = self._best_match(incidents.list(), artifacts)
            if match is None:
                campaign = campaigns.add(
                    Campaign(
                        name=campaign_name,
                        category=category,
                        risk_score=risk_score,
                        artifacts=artifacts,
                        affected_users=recipients,
                    )
                )
                incident = incidents.add(
                    Incident(
                        title=incident_title,
                        category=category,
                        risk_score=risk_score,
                        artifacts=artifacts,
                        scan_ids=(scan_id,),
                        campaign_id=str(campaign.id),
                        affected_users=recipients,
                        events=(),
                    )
                )
                incident.record_event("Incident created", opened_detail)
                incidents.update(incident)
                uow.commit()
                created_incident = True
                created_campaign = True
            else:
                match.attach_detection(
                    scan_id=scan_id,
                    artifacts=artifacts,
                    risk_score=risk_score,
                    recipients=recipients,
                    rationale=link.rationale,
                )
                incident = incidents.update(match)
                campaign = self._update_campaign(
                    campaigns,
                    incident.campaign_id,
                    artifacts,
                    category,
                    risk_score,
                    recipients,
                )
                uow.commit()
                created_incident = False
                created_campaign = False

        if created_incident:
            self._logger.info("Incident opened for {} ({})", subject, category.value)
            self._audit.record(
                _ACTION_OPENED,
                outcome=AuditOutcome.SUCCESS,
                resource=incident.title,
                category=incident.category.value,
                risk_score=incident.risk_score,
            )
        else:
            self._logger.info(
                "Detection correlated into incident '{}' ({})",
                incident.title,
                link.rationale,
            )
            self._audit.record(
                _ACTION_CORRELATED,
                outcome=AuditOutcome.SUCCESS,
                resource=incident.title,
                rationale=link.rationale,
                strength=link.strength,
            )

        return CorrelationOutcome(
            incident=incident,
            campaign=campaign,
            link=link,
            created_incident=created_incident,
            created_campaign=created_campaign,
        )

    # --- queries --------------------------------------------------------

    def list_incidents(self) -> list[Incident]:
        """Return all incidents, most recently seen first."""
        with self._unit_of_work_factory() as uow:
            incidents = uow.get_repository(Incident).list()
        incidents.sort(key=lambda incident: incident.last_seen, reverse=True)
        return incidents

    def get_incident(self, incident_id: str) -> Incident | None:
        """Return one incident by identifier."""
        with self._unit_of_work_factory() as uow:
            for incident in uow.get_repository(Incident).list():
                if str(incident.id) == incident_id:
                    return incident
        return None

    def list_campaigns(self) -> list[Campaign]:
        """Return all campaigns, most recently seen first."""
        with self._unit_of_work_factory() as uow:
            campaigns = uow.get_repository(Campaign).list()
        campaigns.sort(key=lambda campaign: campaign.last_seen, reverse=True)
        return campaigns

    def relationships(self, artifact: ArtifactRef) -> tuple[str, ...]:
        """Describe how one observable relates to known incidents and campaigns.

        Produces the analyst-facing statements the Threat Intelligence surface
        uses, for example that a URL appears across several incidents or that a
        sender belongs to a named campaign.
        """
        with self._unit_of_work_factory() as uow:
            incidents = uow.get_repository(Incident).list()
            campaigns = uow.get_repository(Campaign).list()

        matching = [i for i in incidents if artifact.key in {r.key for r in i.artifacts}]
        statements: list[str] = []
        if matching:
            detections = sum(len(i.scan_ids) for i in matching)
            statements.append(
                f"{artifact.label} appears in {len(matching)} incident(s) "
                f"across {detections} detection(s)."
            )
        campaign_ids = {i.campaign_id for i in matching if i.campaign_id}
        for campaign in campaigns:
            if str(campaign.id) in campaign_ids:
                statements.append(
                    f"{artifact.label} belongs to campaign '{campaign.name}' "
                    f"({campaign.occurrences} occurrence(s), "
                    f"{len(campaign.affected_users)} affected user(s))."
                )
        if not statements:
            statements.append(f"{artifact.label} has no known relationships.")
        return tuple(statements)

    # --- workflow -------------------------------------------------------

    def update_workflow(
        self,
        incident_id: str,
        *,
        status: str | None = None,
        assignee: str | None = None,
        priority: str | None = None,
        tags: tuple[str, ...] | None = None,
        comment: str | None = None,
        author: str = "analyst",
    ) -> Incident | None:
        """Apply an analyst workflow change without touching detection evidence."""
        with self._unit_of_work_factory() as uow:
            repo = uow.get_repository(Incident)
            incident = next((i for i in repo.list() if str(i.id) == incident_id), None)
            if incident is None:
                return None
            if assignee is not None or priority is not None or tags is not None:
                incident.assign(
                    assignee=assignee if assignee is not None else incident.assignee,
                    priority=(
                        InvestigationPriority(priority)
                        if priority is not None
                        else incident.priority
                    ),
                    tags=tags if tags is not None else incident.tags,
                )
            if comment:
                incident.add_comment(author=author, body=comment)
            if status is not None:
                incident.change_status(IncidentStatus(status))
            updated = repo.update(incident)
            uow.commit()

        self._audit.success(
            "incident.workflow",
            resource=updated.title,
            status=updated.status.value,
            assignee=updated.assignee,
        )
        return updated

    # --- helpers --------------------------------------------------------

    @staticmethod
    def _best_match(
        incidents: list[Incident], artifacts: tuple[ArtifactRef, ...]
    ) -> tuple[Incident | None, CorrelationLink]:
        """Return the open incident sharing the most evidence, if any.

        The category artifact alone is deliberately not enough to correlate: two
        unrelated credential-phishing emails share a category but no
        infrastructure, so a match requires at least one non-category observable.
        """
        best: Incident | None = None
        best_link = CorrelationLink(shared=())
        for incident in incidents:
            if not incident.is_open:
                continue
            link = correlate(artifacts, incident.artifacts)
            substantive = tuple(ref for ref in link.shared if ref.kind is not ArtifactKind.CATEGORY)
            if len(substantive) < _MIN_LINK_STRENGTH:
                continue
            if link.strength > best_link.strength:
                best, best_link = incident, link
        return best, best_link

    @staticmethod
    def _update_campaign(
        campaigns: IRepository[Campaign],
        campaign_id: str,
        artifacts: tuple[ArtifactRef, ...],
        category: ThreatCategory,
        risk_score: float,
        recipients: tuple[str, ...],
    ) -> Campaign:
        existing = next((c for c in campaigns.list() if str(c.id) == campaign_id), None)
        if existing is None:
            return campaigns.add(
                Campaign(
                    name=f"Campaign {category.value}",
                    category=category,
                    risk_score=risk_score,
                    artifacts=artifacts,
                    affected_users=recipients,
                )
            )
        existing.register_observation(
            artifacts=artifacts, risk_score=risk_score, recipients=recipients
        )
        return campaigns.update(existing)

    @staticmethod
    def _campaign_name(email: EmailMessage, scan: EmailScan) -> str:
        pattern = subject_pattern(email.subject)
        label = pattern.title() if pattern else email.sender.domain or "Unattributed"
        return f"{scan.category.value.replace('_', ' ').title()}: {label}"

    @staticmethod
    def _incident_title(email: EmailMessage, scan: EmailScan) -> str:
        subject = email.subject or "(no subject)"
        return f"{scan.category.value.replace('_', ' ').title()} - {subject}"

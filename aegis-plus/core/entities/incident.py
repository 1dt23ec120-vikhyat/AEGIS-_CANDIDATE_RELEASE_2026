"""Incident aggregate.

An :class:`Incident` is the unit of analyst work: one or more related malicious
artifacts, the evidence that links them, the campaign they belong to, and the
analyst workflow state (status, priority, assignment, tags, comments).

Detection evidence and analyst judgement are kept apart - ``artifacts`` and
``links`` are appended by the correlation engine, while workflow fields are only
ever changed through :meth:`assign`, :meth:`change_status`, and
:meth:`add_comment`. Correlation never overwrites analyst decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from core.constants import IncidentStatus, InvestigationPriority
from core.domain.correlation import ArtifactRef
from core.domain.intelligence import ThreatCategory
from core.domain.value_objects import EntityId
from core.entities.base import AggregateRoot


@dataclass(frozen=True, slots=True)
class IncidentComment:
    """An analyst comment recorded against an incident."""

    author: str
    body: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class IncidentEvent:
    """A chronological entry in the incident's investigation history."""

    label: str
    detail: str
    occurred_at: datetime


class Incident(AggregateRoot):
    """A correlated group of malicious artifacts under investigation."""

    def __init__(  # noqa: PLR0913 - an aggregate carrying detection and workflow state
        self,
        *,
        title: str,
        category: ThreatCategory,
        risk_score: float,
        status: IncidentStatus = IncidentStatus.OPEN,
        priority: InvestigationPriority = InvestigationPriority.MEDIUM,
        artifacts: tuple[ArtifactRef, ...] = (),
        scan_ids: tuple[str, ...] = (),
        campaign_id: str = "",
        assignee: str = "",
        tags: tuple[str, ...] = (),
        comments: tuple[IncidentComment, ...] = (),
        events: tuple[IncidentEvent, ...] = (),
        occurrences: int = 1,
        affected_users: tuple[str, ...] = (),
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize an incident.

        Args:
            title: Human-readable incident title.
            category: The dominant threat category.
            risk_score: The highest observed risk in ``[0, 1]``.
            status: The investigation lifecycle state.
            priority: The analyst-assigned priority.
            artifacts: Correlatable observables attributed to the incident.
            scan_ids: Identifiers of the detections folded into the incident.
            campaign_id: The campaign this incident belongs to, if any.
            assignee: The analyst who owns the incident.
            tags: Analyst classification tags.
            comments: Analyst comments.
            events: Investigation history entries.
            occurrences: How many detections belong to the incident.
            affected_users: Recipients affected by the incident.
            first_seen: When the incident was first observed.
            last_seen: When the incident was last observed.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp.
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        now = datetime.now(UTC)
        self.title = title
        self.category = category
        self.risk_score = risk_score
        self.status = status
        self.priority = priority
        self.artifacts = artifacts
        self.scan_ids = scan_ids
        self.campaign_id = campaign_id
        self.assignee = assignee
        self.tags = tags
        self.comments = comments
        self.events = events
        self.occurrences = occurrences
        self.affected_users = affected_users
        self.first_seen = first_seen or now
        self.last_seen = last_seen or now

    @property
    def risk_percent(self) -> int:
        """The incident risk as a whole percentage."""
        return round(self.risk_score * 100)

    @property
    def is_open(self) -> bool:
        """Whether the incident still requires analyst attention."""
        return self.status not in (
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        )

    def record_event(self, label: str, detail: str) -> None:
        """Append an entry to the investigation history."""
        self.events = (
            *self.events,
            IncidentEvent(label=label, detail=detail, occurred_at=datetime.now(UTC)),
        )
        self.touch()

    def attach_detection(
        self,
        *,
        scan_id: str,
        artifacts: tuple[ArtifactRef, ...],
        risk_score: float,
        recipients: tuple[str, ...],
        rationale: str,
    ) -> None:
        """Fold a correlated detection into the incident.

        Appends evidence only; analyst workflow state is never modified here.
        """
        known = {ref.key for ref in self.artifacts}
        self.artifacts = self.artifacts + tuple(ref for ref in artifacts if ref.key not in known)
        if scan_id and scan_id not in self.scan_ids:
            self.scan_ids = (*self.scan_ids, scan_id)
        seen_users = set(self.affected_users)
        self.affected_users = self.affected_users + tuple(
            user for user in recipients if user not in seen_users
        )
        self.risk_score = max(self.risk_score, risk_score)
        self.occurrences += 1
        self.last_seen = datetime.now(UTC)
        self.record_event("Detection correlated", rationale)

    def assign(
        self, *, assignee: str, priority: InvestigationPriority, tags: tuple[str, ...]
    ) -> None:
        """Set ownership and triage metadata."""
        self.assignee = assignee
        self.priority = priority
        self.tags = tags
        self.record_event(
            "Assignment updated",
            f"Assigned to {assignee or 'unassigned'} at {priority.value} priority",
        )

    def change_status(self, status: IncidentStatus, *, note: str = "") -> None:
        """Move the incident through its lifecycle."""
        previous = self.status
        self.status = status
        detail = f"{previous.value} to {status.value}"
        self.record_event("Status changed", f"{detail}. {note}".strip())

    def add_comment(self, *, author: str, body: str) -> None:
        """Record an analyst comment."""
        self.comments = (
            *self.comments,
            IncidentComment(author=author, body=body, created_at=datetime.now(UTC)),
        )
        self.record_event("Comment added", f"{author}: {body}")

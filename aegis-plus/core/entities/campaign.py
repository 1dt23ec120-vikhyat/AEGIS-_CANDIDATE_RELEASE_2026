"""Campaign aggregate.

A :class:`Campaign` groups related malicious observations that share attacker
infrastructure or lures - the same sender, reply-to, lookalike domain, subject
pattern, URL, or attachment. It accumulates occurrences and affected recipients
over time so an analyst sees the shape of an ongoing operation rather than a
stream of isolated detections.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.domain.correlation import ArtifactRef
from core.domain.intelligence import ThreatCategory
from core.domain.value_objects import EntityId
from core.entities.base import AggregateRoot


class Campaign(AggregateRoot):
    """A group of related malicious observations."""

    def __init__(  # noqa: PLR0913 - a data-carrying aggregate with many persisted fields
        self,
        *,
        name: str,
        category: ThreatCategory,
        risk_score: float,
        artifacts: tuple[ArtifactRef, ...] = (),
        occurrences: int = 1,
        affected_users: tuple[str, ...] = (),
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        entity_id: EntityId | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Initialize a campaign.

        Args:
            name: Human-readable campaign name.
            category: The dominant threat category.
            risk_score: The highest observed risk in ``[0, 1]``.
            artifacts: Correlatable observables attributed to the campaign.
            occurrences: How many observations belong to the campaign.
            affected_users: Recipients targeted by the campaign.
            first_seen: When the campaign was first observed.
            last_seen: When the campaign was last observed.
            entity_id: Identity; generated if omitted.
            created_at: Creation timestamp.
            updated_at: Last-modified timestamp.
        """
        super().__init__(entity_id=entity_id, created_at=created_at, updated_at=updated_at)
        now = datetime.now(UTC)
        self.name = name
        self.category = category
        self.risk_score = risk_score
        self.artifacts = artifacts
        self.occurrences = occurrences
        self.affected_users = affected_users
        self.first_seen = first_seen or now
        self.last_seen = last_seen or now

    @property
    def risk_percent(self) -> int:
        """The campaign risk as a whole percentage."""
        return round(self.risk_score * 100)

    def register_observation(
        self,
        *,
        artifacts: tuple[ArtifactRef, ...],
        risk_score: float,
        recipients: tuple[str, ...],
    ) -> None:
        """Fold a newly correlated observation into the campaign."""
        known = {ref.key for ref in self.artifacts}
        self.artifacts = self.artifacts + tuple(ref for ref in artifacts if ref.key not in known)
        seen_users = set(self.affected_users)
        self.affected_users = self.affected_users + tuple(
            user for user in recipients if user not in seen_users
        )
        self.risk_score = max(self.risk_score, risk_score)
        self.occurrences += 1
        self.last_seen = datetime.now(UTC)
        self.touch()

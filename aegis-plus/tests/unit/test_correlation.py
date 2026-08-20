"""Tests for the correlation domain and incident/campaign aggregates."""

from __future__ import annotations

from core.constants import IncidentStatus, InvestigationPriority
from core.domain.correlation import (
    ArtifactKind,
    ArtifactRef,
    correlate,
    subject_pattern,
)
from core.domain.intelligence import ThreatCategory
from core.entities import Campaign, Incident


def test_subject_pattern_collapses_templated_lures() -> None:
    assert subject_pattern("Invoice 4821 overdue") == subject_pattern("Invoice 9142 overdue")
    assert subject_pattern("RE: Invoice 4821 overdue!") == subject_pattern("Invoice 9142 overdue")


def test_subject_pattern_distinguishes_unrelated_subjects() -> None:
    assert subject_pattern("Invoice overdue") != subject_pattern("Team lunch tomorrow")


def test_artifact_ref_key_and_label() -> None:
    ref = ArtifactRef(ArtifactKind.SENDER, "a@b.com")
    assert ref.key == "sender:a@b.com"
    assert "Sender" in ref.label


def test_correlate_returns_shared_observables() -> None:
    new = (
        ArtifactRef(ArtifactKind.SENDER, "a@b.com"),
        ArtifactRef(ArtifactKind.URL, "http://x"),
        ArtifactRef(ArtifactKind.DOMAIN, "b.com"),
    )
    existing = (
        ArtifactRef(ArtifactKind.SENDER, "a@b.com"),
        ArtifactRef(ArtifactKind.DOMAIN, "b.com"),
    )
    link = correlate(new, existing)
    assert link.strength == 2
    assert ArtifactKind.SENDER in link.kinds
    assert "shared" in link.rationale.lower()


def test_correlate_with_nothing_in_common() -> None:
    link = correlate(
        (ArtifactRef(ArtifactKind.SENDER, "a@b.com"),),
        (ArtifactRef(ArtifactKind.SENDER, "z@q.com"),),
    )
    assert link.strength == 0
    assert link.rationale == "No shared indicators"


def test_campaign_registers_observation() -> None:
    campaign = Campaign(
        name="Test",
        category=ThreatCategory.PHISHING,
        risk_score=0.5,
        artifacts=(ArtifactRef(ArtifactKind.SENDER, "a@b.com"),),
        affected_users=("one@corp.com",),
    )
    campaign.register_observation(
        artifacts=(
            ArtifactRef(ArtifactKind.SENDER, "a@b.com"),
            ArtifactRef(ArtifactKind.URL, "http://x"),
        ),
        risk_score=0.9,
        recipients=("one@corp.com", "two@corp.com"),
    )
    assert campaign.occurrences == 2
    assert campaign.risk_score == 0.9
    assert len(campaign.artifacts) == 2
    assert campaign.affected_users == ("one@corp.com", "two@corp.com")


def _incident() -> Incident:
    return Incident(
        title="Test incident",
        category=ThreatCategory.PHISHING,
        risk_score=0.6,
        artifacts=(ArtifactRef(ArtifactKind.SENDER, "a@b.com"),),
        scan_ids=("scan-1",),
        affected_users=("one@corp.com",),
    )


def test_incident_attach_detection_appends_evidence_only() -> None:
    incident = _incident()
    incident.assign(assignee="alice", priority=InvestigationPriority.HIGH, tags=("phishing",))
    incident.attach_detection(
        scan_id="scan-2",
        artifacts=(ArtifactRef(ArtifactKind.URL, "http://x"),),
        risk_score=0.95,
        recipients=("two@corp.com",),
        rationale="Shared sender",
    )
    assert incident.occurrences == 2
    assert incident.scan_ids == ("scan-1", "scan-2")
    assert incident.risk_score == 0.95
    # Analyst workflow must survive correlation untouched.
    assert incident.assignee == "alice"
    assert incident.priority is InvestigationPriority.HIGH
    assert incident.tags == ("phishing",)


def test_incident_status_lifecycle_records_history() -> None:
    incident = _incident()
    incident.change_status(IncidentStatus.INVESTIGATING)
    incident.add_comment(author="alice", body="Confirmed phishing")
    incident.change_status(IncidentStatus.RESOLVED, note="Blocked sender")
    assert incident.status is IncidentStatus.RESOLVED
    assert not incident.is_open
    labels = [e.label for e in incident.events]
    assert labels.count("Status changed") == 2
    assert "Comment added" in labels
    assert incident.comments[0].author == "alice"


def test_incident_is_open_for_active_states() -> None:
    incident = _incident()
    assert incident.is_open
    incident.change_status(IncidentStatus.CONTAINED)
    assert incident.is_open
    incident.change_status(IncidentStatus.FALSE_POSITIVE)
    assert not incident.is_open

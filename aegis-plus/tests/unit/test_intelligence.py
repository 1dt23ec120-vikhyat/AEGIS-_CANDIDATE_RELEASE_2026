"""Tests for the evidence-combination policy."""

from __future__ import annotations

import pytest

from core.domain import Verdict
from core.domain.intelligence import (
    Evidence,
    EvidenceSource,
    ThreatCategory,
    combine_evidence,
)

pytestmark = pytest.mark.unit

_SUS = 0.35
_PHISH = 0.70


def _ev(
    source: EvidenceSource,
    risk: float,
    conf: float,
    *,
    available: bool = True,
    category: ThreatCategory = ThreatCategory.NONE,
) -> Evidence:
    return Evidence(
        source=source,
        risk=risk,
        confidence=conf,
        weight=1.0,
        rationale="test",
        category=category,
        available=available,
    )


def test_no_available_evidence_is_legitimate() -> None:
    report = combine_evidence(
        (_ev(EvidenceSource.REPUTATION, 0.9, 0.9, available=False),),
        suspicious_threshold=_SUS,
        phishing_threshold=_PHISH,
    )
    assert report.verdict is Verdict.LEGITIMATE
    assert report.risk_score == 0.0
    assert report.evidence_strength == 0.0


def test_confident_source_is_not_diluted_by_clean_sources() -> None:
    evidences = (
        _ev(EvidenceSource.ML, 0.95, 0.95, category=ThreatCategory.PHISHING),
        _ev(EvidenceSource.DOMAIN, 0.0, 0.75),
        _ev(EvidenceSource.THREAT_INTEL, 0.0, 0.9),
    )
    report = combine_evidence(evidences, suspicious_threshold=_SUS, phishing_threshold=_PHISH)
    assert report.verdict is Verdict.PHISHING
    assert report.primary_category is ThreatCategory.PHISHING


def test_unavailable_sources_excluded_from_strength() -> None:
    evidences = (
        _ev(EvidenceSource.ML, 0.1, 0.6),
        _ev(EvidenceSource.REPUTATION, 0.9, 0.9, available=False),
    )
    report = combine_evidence(evidences, suspicious_threshold=_SUS, phishing_threshold=_PHISH)
    assert report.verdict is Verdict.LEGITIMATE
    assert len(report.available_sources) == 1
    assert report.source_scores[1].available is False


def test_corroborating_moderate_sources_raise_suspicion() -> None:
    evidences = (
        _ev(EvidenceSource.ML, 0.4, 0.8, category=ThreatCategory.SUSPICIOUS_STRUCTURE),
        _ev(EvidenceSource.DOMAIN, 0.45, 0.75, category=ThreatCategory.DECEPTIVE_DOMAIN),
    )
    report = combine_evidence(evidences, suspicious_threshold=_SUS, phishing_threshold=_PHISH)
    assert report.verdict is Verdict.SUSPICIOUS

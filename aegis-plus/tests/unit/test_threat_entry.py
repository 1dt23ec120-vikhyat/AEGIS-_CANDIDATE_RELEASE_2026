"""Tests for the ThreatEntry aggregate and URL fingerprinting."""

from __future__ import annotations

import pytest

from core.constants import BlockSource
from core.domain import Url, Verdict
from core.domain.analysis import FeatureContribution, UrlAnalysis
from core.entities import ThreatEntry

pytestmark = pytest.mark.unit


def _analysis() -> UrlAnalysis:
    return UrlAnalysis(
        verdict=Verdict.PHISHING,
        threat_score=0.82,
        confidence=0.6,
        features={"url_length": 30},
        contributions=(
            FeatureContribution("ip_address_used", "Host is an IP", 0.3, True),
            FeatureContribution("https_used", "No HTTPS", 0.14, False),
        ),
    )


def test_fingerprint_is_stable_and_distinct() -> None:
    a = Url.create("http://bad.example/login")
    b = Url.create("http://bad.example/login")
    c = Url.create("http://other.example")
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != c.fingerprint
    assert len(a.fingerprint) == 64


def test_from_analysis_populates_metadata() -> None:
    url = Url.create("http://192.168.0.1/login@verify.example")
    entry = ThreatEntry.from_analysis(url, _analysis(), source=BlockSource.AI)

    assert entry.artifact == str(url)
    assert entry.artifact_hash == url.fingerprint
    assert entry.verdict is Verdict.PHISHING
    assert entry.risk_score == 0.82
    assert entry.blocked is True
    assert entry.block_source is BlockSource.AI
    assert entry.detection_count == 1
    # Only triggered indicators are retained.
    assert all(i.triggered for i in entry.indicators)


def test_register_detection_increments_and_updates() -> None:
    url = Url.create("http://bad.example")
    entry = ThreatEntry.from_analysis(url, _analysis())
    first_seen = entry.first_detected
    entry.register_detection()
    assert entry.detection_count == 2
    assert entry.first_detected == first_seen
    assert entry.last_detected >= first_seen

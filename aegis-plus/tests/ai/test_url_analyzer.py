"""Tests for the heuristic URL analyzer."""

from __future__ import annotations

import pytest

from ai.url_analysis import HeuristicUrlAnalyzer
from core.domain import Url, Verdict

pytestmark = pytest.mark.unit


@pytest.fixture
def analyzer() -> HeuristicUrlAnalyzer:
    return HeuristicUrlAnalyzer()


def test_benign_url_is_legitimate(analyzer: HeuristicUrlAnalyzer) -> None:
    result = analyzer.analyze(Url.create("https://www.google.com"))
    assert result.verdict is Verdict.LEGITIMATE
    assert result.threat_score < 0.35
    assert 0.5 <= result.confidence <= 1.0


def test_phishing_url_is_flagged(analyzer: HeuristicUrlAnalyzer) -> None:
    url = Url.create(
        "http://192.168.10.5/login@paypal-verify-account-update-secure.example.com/signin?password=1"
    )
    result = analyzer.analyze(url)

    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.PHISHING)
    triggered = {c.feature for c in result.contributions if c.triggered}
    assert {"ip_address_used", "at_symbol_present", "suspicious_keywords"} <= triggered


def test_score_ordering_and_determinism(analyzer: HeuristicUrlAnalyzer) -> None:
    benign = analyzer.analyze(Url.create("https://www.wikipedia.org"))
    phishing = analyzer.analyze(Url.create("http://192.168.0.1/verify-account@login.example.com"))
    assert phishing.threat_score > benign.threat_score

    again = analyzer.analyze(Url.create("https://www.wikipedia.org"))
    assert again.threat_score == benign.threat_score


def test_explanation_present(analyzer: HeuristicUrlAnalyzer) -> None:
    result = analyzer.analyze(Url.create("http://bit.ly/x"))
    assert len(result.contributions) > 0
    assert result.risk_percent == round(result.threat_score * 100)

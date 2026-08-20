"""Tests for URL feature extraction."""

from __future__ import annotations

import pytest

from ai.url_analysis import extract_features
from core.domain import Url

pytestmark = pytest.mark.unit


def test_extracts_expected_lexical_and_structural_features() -> None:
    url = Url.create("http://192.168.0.10/secure-login@verify.example.com/update?x=1")
    features = extract_features(url)

    assert features["ip_address_used"] is True
    assert features["https_used"] is False
    assert features["at_symbol_present"] is True
    assert features["suspicious_keywords"] >= 1
    assert features["hyphen_count"] == 1
    assert features["url_length"] == len(url.raw)
    assert features["url_entropy"] > 0


def test_benign_url_features() -> None:
    features = extract_features(Url.create("https://www.google.com"))
    assert features["https_used"] is True
    assert features["ip_address_used"] is False
    assert features["at_symbol_present"] is False
    assert features["suspicious_keywords"] == 0


def test_shortener_detected() -> None:
    assert extract_features(Url.create("https://bit.ly/abc"))["shortened_url"] is True
    assert extract_features(Url.create("https://example.com/abc"))["shortened_url"] is False

"""Tests for the offline structural domain intelligence provider."""

from __future__ import annotations

import pytest

from ai.url_analysis import StructuralDomainIntelligenceProvider
from core.domain import ThreatCategory
from core.domain.url import Url

pytestmark = pytest.mark.unit


def _assess(raw: str) -> object:
    return StructuralDomainIntelligenceProvider().assess(Url.create(raw))


def _fired(evidence: object) -> set[str]:
    return {c.feature for c in evidence.contributions if c.triggered}  # type: ignore[attr-defined]


def test_clean_domain_has_no_risk() -> None:
    evidence = _assess("https://www.wikipedia.org/wiki/Security")
    assert evidence.risk == 0.0  # type: ignore[attr-defined]
    assert evidence.category is ThreatCategory.NONE  # type: ignore[attr-defined]


def test_homograph_domain_is_deceptive() -> None:
    # Cyrillic small a (U+0430) substituted for Latin a.
    evidence = _assess("https://p\u0430ypal.com/login")
    assert evidence.category is ThreatCategory.DECEPTIVE_DOMAIN  # type: ignore[attr-defined]
    assert "homograph_domain" in _fired(evidence)
    assert evidence.risk > 0.0  # type: ignore[attr-defined]


def test_punycode_domain_flagged() -> None:
    evidence = _assess("http://xn--pypal-4ve.com/login")
    assert "punycode_domain" in _fired(evidence)


def test_embedded_credentials_flagged() -> None:
    evidence = _assess("http://user:pass@secure.example.com/login")
    assert "embedded_credentials" in _fired(evidence)


def test_suspicious_tld_flagged() -> None:
    evidence = _assess("http://account-verify.xyz/login")
    assert "suspicious_tld" in _fired(evidence)

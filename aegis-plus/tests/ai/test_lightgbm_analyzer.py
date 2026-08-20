"""Tests for the LightGBM analyzer and its heuristic fallback."""

from __future__ import annotations

import pytest

from ai.url_analysis import HeuristicUrlAnalyzer, LightGBMUrlAnalyzer
from config import ProjectPaths
from core.domain import EvidenceSource, Verdict
from core.domain.url import Url
from infrastructure.ai import LightGbmModelLoader
from infrastructure.logging import get_logger

pytestmark = pytest.mark.unit


def _analyzer_with_model() -> LightGBMUrlAnalyzer:
    model = LightGbmModelLoader(
        ProjectPaths.create().models_dir / "url_lightgbm.txt", get_logger("test")
    ).load()
    return LightGBMUrlAnalyzer(model, HeuristicUrlAnalyzer(), get_logger("test"))


def test_source_is_ml() -> None:
    assert _analyzer_with_model().source is EvidenceSource.ML


def test_predicts_phishing_for_malicious_url() -> None:
    analyzer = _analyzer_with_model()
    result = analyzer.analyze(
        Url.create("http://192.168.10.5/login@paypal-verify.example.com/signin?password=1")
    )
    assert result.verdict is Verdict.PHISHING
    assert result.threat_score > 0.7
    assert result.contributions  # SHAP explanations present


def test_predicts_legitimate_for_benign_url() -> None:
    result = _analyzer_with_model().analyze(Url.create("https://www.google.com"))
    assert result.verdict is Verdict.LEGITIMATE


def test_contributions_are_json_native_types() -> None:
    import json

    result = _analyzer_with_model().analyze(
        Url.create("http://192.168.10.5/login@evil.example.com/verify?password=1")
    )
    for contribution in result.contributions:
        assert type(contribution.weight) is float
        assert type(contribution.triggered) is bool
        # Must be serializable for JSON persistence (no numpy scalars).
        json.dumps({"w": contribution.weight, "t": contribution.triggered})


def test_falls_back_when_model_missing() -> None:
    fallback = HeuristicUrlAnalyzer()
    analyzer = LightGBMUrlAnalyzer(None, fallback, get_logger("test"))
    url = Url.create("http://192.168.1.1/login@evil.example.com/verify?password=1")
    ml_result = analyzer.analyze(url)
    heuristic_result = fallback.analyze(url)
    assert ml_result.verdict is heuristic_result.verdict

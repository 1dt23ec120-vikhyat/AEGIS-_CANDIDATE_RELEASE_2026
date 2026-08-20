"""LightGBM URL analyzer.

A gradient-boosted classifier implementing the Core ``IUrlAnalyzer`` port. It
produces a calibrated phishing probability and explains it with per-feature SHAP
contributions. The trained booster is loaded by the infrastructure layer and
injected here, so this analyzer never performs I/O.

**Current model status:** the bundled booster (``url_lightgbm.txt``) is a
**demonstration model** trained on a synthetic dataset. It validates the ML
infrastructure end-to-end but is **not a production-quality phishing classifier**.
When a real labelled dataset is available, a production model can replace it
without any architectural changes — only the artifact file changes.

If no model is available — or a prediction fails at runtime — it transparently
delegates to the injected heuristic analyzer, so detection degrades gracefully
rather than failing.
"""

from __future__ import annotations

from typing import Any

from ai.url_analysis.features import MODEL_FEATURE_NAMES, extract_features, feature_vector
from core.domain.analysis import FeatureContribution, UrlAnalysis, Verdict
from core.domain.intelligence import EvidenceSource
from core.domain.url import Url
from core.interfaces import ILogger, IUrlAnalyzer

_DEFAULT_SUSPICIOUS_THRESHOLD = 0.35
_DEFAULT_PHISHING_THRESHOLD = 0.70
_TOP_CONTRIBUTIONS = 8

_FEATURE_DETAIL = {
    "ip_address_used": "Model weighted the raw-IP host as high risk",
    "at_symbol_present": "Model weighted the embedded '@' as high risk",
    "suspicious_keywords": "Model weighted phishing keywords as high risk",
    "shortened_url": "Model weighted the URL shortener as risky",
    "https_used": "Model weighted the absence of HTTPS as risky",
    "subdomain_count": "Model weighted deep subdomain nesting as risky",
    "url_length": "Model weighted the URL length as risky",
    "url_entropy": "Model weighted the URL's high entropy as risky",
    "host_digit_ratio": "Model weighted the digit-heavy host as risky",
    "hyphen_count": "Model weighted the many hyphens as risky",
    "encoded_characters": "Model weighted percent-encoding as risky",
    "dot_count": "Model weighted the many dots as risky",
}


class LightGBMUrlAnalyzer(IUrlAnalyzer):
    """A trained LightGBM classifier with explainability and fallback."""

    def __init__(
        self,
        model: Any,
        fallback: IUrlAnalyzer,
        logger: ILogger,
        *,
        suspicious_threshold: float = _DEFAULT_SUSPICIOUS_THRESHOLD,
        phishing_threshold: float = _DEFAULT_PHISHING_THRESHOLD,
    ) -> None:
        """Initialize the analyzer.

        Args:
            model: A loaded LightGBM booster, or ``None`` to force fallback.
            fallback: The analyzer used when the model is unavailable.
            logger: Injected logger.
            suspicious_threshold: Score at/above which a URL is suspicious.
            phishing_threshold: Score at/above which a URL is phishing.
        """
        self._model = model
        self._fallback = fallback
        self._logger = logger
        self._suspicious_threshold = suspicious_threshold
        self._phishing_threshold = phishing_threshold

    @property
    def source(self) -> EvidenceSource:
        """Machine-learning evidence source."""
        return EvidenceSource.ML

    def analyze(self, url: Url) -> UrlAnalysis:
        """Analyze a URL with the trained model, falling back on failure."""
        if self._model is None:
            return self._fallback.analyze(url)
        try:
            return self._predict(url)
        except Exception as exc:  # broad: any inference failure -> graceful fallback
            self._logger.warning("ML inference failed, using fallback: {}", exc)
            return self._fallback.analyze(url)

    def _predict(self, url: Url) -> UrlAnalysis:
        import numpy as np

        features = extract_features(url)
        vector = np.asarray([feature_vector(features)], dtype=float)

        probability = float(self._model.predict(vector)[0])
        threat_score = round(probability, 4)
        verdict = self._verdict(threat_score)
        confidence = round(abs(threat_score - 0.5) * 2, 4)

        contributions = self._explain(vector)
        return UrlAnalysis(
            verdict=verdict,
            threat_score=threat_score,
            confidence=confidence,
            features=features,
            contributions=contributions,
        )

    def _explain(self, vector: Any) -> tuple[FeatureContribution, ...]:
        """Derive per-feature contributions from the model's SHAP values."""
        shap = self._model.predict(vector, pred_contrib=True)[0]
        # The final SHAP element is the base value; the rest align with features.
        pairs = list(zip(MODEL_FEATURE_NAMES, shap[:-1], strict=False))
        ranked = sorted(pairs, key=lambda p: abs(p[1]), reverse=True)[:_TOP_CONTRIBUTIONS]
        contributions = [
            FeatureContribution(
                feature=name,
                detail=_FEATURE_DETAIL.get(name, f"Model weighted {name.replace('_', ' ')}"),
                weight=round(float(abs(value)), 4),
                triggered=bool(value > 0),
            )
            for name, value in ranked
            if value != 0
        ]
        return tuple(contributions)

    def _verdict(self, score: float) -> Verdict:
        if score >= self._phishing_threshold:
            return Verdict.PHISHING
        if score >= self._suspicious_threshold:
            return Verdict.SUSPICIOUS
        return Verdict.LEGITIMATE

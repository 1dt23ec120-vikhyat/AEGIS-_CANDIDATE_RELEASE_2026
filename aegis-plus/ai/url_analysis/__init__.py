"""URL analysis AI pipeline.

Deterministic feature extraction, an explainable heuristic analyzer and a
LightGBM analyzer (both behind the Core ``IUrlAnalyzer`` port), plus offline
domain intelligence and a default reputation provider.

**Model status:** the bundled LightGBM booster is a **demonstration model**
trained on synthetic data. It validates the ML infrastructure but is not a
production-quality classifier. A production model trained on a real labelled
corpus replaces it without architectural changes — only the artifact file changes.
"""

from ai.url_analysis.analyzer import HeuristicUrlAnalyzer
from ai.url_analysis.domain_intelligence import StructuralDomainIntelligenceProvider
from ai.url_analysis.features import extract_features
from ai.url_analysis.lightgbm_analyzer import LightGBMUrlAnalyzer
from ai.url_analysis.reputation import NullReputationProvider

__all__ = [
    "HeuristicUrlAnalyzer",
    "LightGBMUrlAnalyzer",
    "NullReputationProvider",
    "StructuralDomainIntelligenceProvider",
    "extract_features",
]

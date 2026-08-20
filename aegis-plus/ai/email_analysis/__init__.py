"""Email analysis AI pipeline.

Offline evidence providers (header, authentication, sender, language, attachment)
and the hybrid analyzer that combines them - plus caller-supplied embedded-URL and
threat-intelligence evidence - through the shared ``combine_evidence`` policy.
"""

from ai.email_analysis.hybrid_analyzer import HybridEmailAnalyzer
from ai.email_analysis.providers import (
    AttachmentProvider,
    AuthenticationProvider,
    HeaderAnalysisProvider,
    LanguageProvider,
    SenderReputationProvider,
)

__all__ = [
    "AttachmentProvider",
    "AuthenticationProvider",
    "HeaderAnalysisProvider",
    "HybridEmailAnalyzer",
    "LanguageProvider",
    "SenderReputationProvider",
]

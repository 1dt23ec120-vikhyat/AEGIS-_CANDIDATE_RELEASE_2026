"""AI subsystem configuration schema.

Holds configuration for the AI subsystem: model paths plus the URL Intelligence
Engine's tunable thresholds, source weights, and provider toggles. Moving these
into configuration (rather than hardcoding) satisfies the milestone's
configuration requirement and NFR §14.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from config import defaults


class AISettings(BaseModel):
    """AI subsystem configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    models_dir: str = Field(default=defaults.DEFAULT_MODELS_DIR, min_length=1)
    model_registry_file: str = Field(default=defaults.DEFAULT_MODEL_REGISTRY_FILE, min_length=1)
    url_model_file: str = Field(default="url_lightgbm.txt", min_length=1)
    use_ml_analyzer: bool = Field(default=True)

    suspicious_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    phishing_threshold: float = Field(default=0.70, ge=0.0, le=1.0)

    weight_ml: float = Field(default=1.0, ge=0.0)
    weight_heuristic: float = Field(default=0.8, ge=0.0)
    weight_reputation: float = Field(default=1.2, ge=0.0)
    weight_threat_intel: float = Field(default=1.5, ge=0.0)
    weight_domain: float = Field(default=0.9, ge=0.0)

    reputation_enabled: bool = Field(default=False)
    reputation_timeout_seconds: float = Field(default=5.0, gt=0.0)
    cache_ttl_seconds: int = Field(default=3600, ge=0)
    redirect_max_depth: int = Field(default=10, ge=0, le=50)

    email_suspicious_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    email_phishing_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    weight_header: float = Field(default=0.9, ge=0.0)
    weight_authentication: float = Field(default=1.3, ge=0.0)
    weight_sender: float = Field(default=1.2, ge=0.0)
    weight_language: float = Field(default=1.0, ge=0.0)
    weight_attachment: float = Field(default=1.1, ge=0.0)
    weight_email_url: float = Field(default=1.4, ge=0.0)

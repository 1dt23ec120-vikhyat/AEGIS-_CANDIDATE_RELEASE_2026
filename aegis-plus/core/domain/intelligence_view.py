"""Threat intelligence contracts (view DTOs) for M11 Phase B.

Immutable, framework-free value objects produced by the deterministic
intelligence services (IOC, campaign, and threat scoring). Every scored field is
in ``[0, 1]`` unless noted, and each scoring DTO carries a ``rationale`` — the
plain-language *why* behind the numbers.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IOCIntelligence:
    """Deterministic intelligence about a single IOC node."""

    ioc_id: str
    label: str = ""
    frequency: int = 0
    prevalence: float = 0.0
    reuse_count: int = 0
    confidence: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    aging_days: float = 0.0
    risk_percent: int = 0
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CampaignIntelligence:
    """Deterministic intelligence about a campaign node."""

    campaign_id: str
    label: str = ""
    artifact_count: int = 0
    ioc_count: int = 0
    infrastructure_count: int = 0
    shared_ioc_score: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    evolution_days: float = 0.0
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CampaignSimilarity:
    """Similarity between two campaigns by shared infrastructure/IOCs."""

    campaign_a: str
    campaign_b: str
    shared_iocs: int = 0
    shared_infrastructure: int = 0
    similarity: float = 0.0
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ThreatScore:
    """A deterministic, explainable threat score for an artifact."""

    artifact_id: str
    label: str = ""
    severity: float = 0.0
    confidence: float = 0.0
    exposure: float = 0.0
    blast_radius: int = 0
    priority: float = 0.0
    analyst_urgency: float = 0.0
    rationale: tuple[str, ...] = ()

"""Shared domain enumerations.

Foundational enumerations that belong to the domain and are shared across
layers. As a Core-owned contract, these originate here rather than in any
infrastructure package (core-contracts standard).
"""

from __future__ import annotations

from enum import Enum


class AuditOutcome(str, Enum):
    """Outcome classification for an audited action."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class BlockSource(str, Enum):
    """Origin of a blacklist decision."""

    AI = "ai"
    USER = "user"
    ADMIN = "admin"


class ArtifactType(str, Enum):
    """The kind of artifact a threat entry describes."""

    URL = "url"
    EMAIL = "email"
    FILE = "file"


class InvestigationStatus(str, Enum):
    """The analyst's investigation state for an email."""

    OPEN = "open"
    UNDER_INVESTIGATION = "under_investigation"
    CONFIRMED_THREAT = "confirmed_threat"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class InvestigationPriority(str, Enum):
    """The analyst-assigned priority for an investigation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    """The lifecycle state of an incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

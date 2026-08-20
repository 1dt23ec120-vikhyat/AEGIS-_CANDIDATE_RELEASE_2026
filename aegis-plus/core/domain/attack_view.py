"""Attack analysis contracts (view DTOs) for M11 Phase C.

Immutable, framework-free value objects produced by the deterministic
:class:`services.analytics.attack_analysis.AttackAnalysisService`. Each carries a
plain-language ``rationale`` so every reconstruction is explainable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AttackChainStep:
    """One ordered step in a reconstructed attack chain."""

    order: int
    node_id: str
    node_type: str
    label: str
    kill_chain_phase: str
    timestamp: str = ""


@dataclass(frozen=True, slots=True)
class AttackChain:
    """An ordered reconstruction of an attack from origin to target."""

    origin_id: str = ""
    target_id: str = ""
    steps: tuple[AttackChainStep, ...] = ()
    rationale: tuple[str, ...] = ()

    @property
    def length(self) -> int:
        """Number of steps in the chain."""
        return len(self.steps)


@dataclass(frozen=True, slots=True)
class KillChainMapping:
    """Nodes mapped to kill-chain phases (deterministic)."""

    phases: tuple[tuple[str, tuple[str, ...]], ...] = ()
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CompromisePath:
    """A discovered compromise path between two nodes."""

    source_id: str = ""
    target_id: str = ""
    node_ids: tuple[str, ...] = ()
    hops: int = 0
    rationale: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Whether the path contains no nodes."""
        return not self.node_ids


@dataclass(frozen=True, slots=True)
class RootCause:
    """The inferred root cause (origin) of an incident subgraph."""

    incident_id: str = ""
    root_id: str = ""
    root_type: str = ""
    root_label: str = ""
    first_seen: str = ""
    evidence_ids: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """A single time-ordered relationship observation."""

    timestamp: str
    source_id: str
    target_id: str
    relationship: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class AttackTimeline:
    """A time-ordered reconstruction of an attack's observed relationships."""

    root_id: str = ""
    entries: tuple[TimelineEntry, ...] = ()
    span_days: float = 0.0
    rationale: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InfrastructureCluster:
    """A cluster of artifacts sharing one infrastructure node."""

    infra_id: str = ""
    infra_type: str = ""
    infra_label: str = ""
    member_ids: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()

    @property
    def size(self) -> int:
        """Number of artifacts in the cluster."""
        return len(self.member_ids)

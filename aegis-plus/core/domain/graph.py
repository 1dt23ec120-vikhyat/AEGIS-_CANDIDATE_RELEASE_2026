"""Knowledge Graph domain model.

Immutable, storage-agnostic value objects for the intelligence knowledge graph.
The graph is the product — visualization is one consumer. Every object uses
stable string identifiers so the same model works with an in-memory dict, Neo4j,
Neptune, JanusGraph, or Cosmos DB Gremlin.

All VOs are frozen dataclasses with no I/O and no framework dependency.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

# ---------------------------------------------------------------------------
# Node taxonomy
# ---------------------------------------------------------------------------


class NodeType(str, Enum):
    """The taxonomy of graph nodes."""

    ARTIFACT = "artifact"
    URL = "url"
    DOMAIN = "domain"
    FILE = "file"
    EMAIL = "email"
    HASH = "hash"
    IOC = "ioc"
    THREAT = "threat"
    INCIDENT = "incident"
    CAMPAIGN = "campaign"
    INVESTIGATION = "investigation"
    PROVIDER = "provider"
    IP_ADDRESS = "ip_address"


# ---------------------------------------------------------------------------
# Relationship taxonomy
# ---------------------------------------------------------------------------


class RelationshipType(str, Enum):
    """Strongly typed relationship labels."""

    CONTAINS = "contains"
    REFERENCES = "references"
    SHARES_IOC = "shares_ioc"
    RELATED_TO = "related_to"
    DOWNLOADED_FROM = "downloaded_from"
    DELIVERED_BY = "delivered_by"
    GENERATED = "generated"
    OBSERVED_IN = "observed_in"
    TARGETS = "targets"
    ASSOCIATED_WITH = "associated_with"
    ANALYZED_BY = "analyzed_by"
    CORRELATED_TO = "correlated_to"
    MEMBER_OF = "member_of"


# ---------------------------------------------------------------------------
# Graph Node
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _node_id() -> str:
    return str(uuid.uuid4())


@dataclass(frozen=True, slots=True)
class GraphNode:
    """An immutable node in the knowledge graph."""

    node_id: str = field(default_factory=_node_id)
    node_type: NodeType = NodeType.ARTIFACT
    display_name: str = ""
    labels: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    @property
    def key(self) -> str:
        """A deduplication key: type + node_id."""
        return f"{self.node_type.value}:{self.node_id}"


# ---------------------------------------------------------------------------
# Graph Edge
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A directed, typed relationship between two nodes."""

    edge_id: str = field(default_factory=_node_id)
    relationship: RelationshipType = RelationshipType.RELATED_TO
    source_id: str = ""
    target_id: str = ""
    confidence: float = 1.0
    provenance: str = ""
    timestamp: str = field(default_factory=_now_iso)
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """A deduplication key: source → relationship → target."""
        return f"{self.source_id}->{self.relationship.value}->{self.target_id}"


# ---------------------------------------------------------------------------
# Graph Path
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphPath:
    """An ordered sequence of nodes and edges forming a traversal path."""

    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()

    @property
    def length(self) -> int:
        """The number of edges (hops) in the path."""
        return len(self.edges)

    @property
    def is_empty(self) -> bool:
        """Whether the path has no nodes."""
        return len(self.nodes) == 0


# ---------------------------------------------------------------------------
# Graph Snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphSnapshot:
    """A point-in-time summary of the knowledge graph."""

    node_count: int = 0
    edge_count: int = 0
    node_type_counts: dict[str, int] = field(default_factory=dict)
    relationship_type_counts: dict[str, int] = field(default_factory=dict)
    duplicate_suppressions: int = 0
    build_duration_ms: float = 0.0

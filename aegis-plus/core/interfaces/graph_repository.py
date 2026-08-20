"""Graph repository port.

Core-owned contract for knowledge graph storage. The in-memory implementation
ships with this release; a future Neo4j, Neptune, JanusGraph, or Cosmos DB
adapter satisfies the same interface without changing application code.

The query methods prepare extension points for future graph analytics
(centrality, components, community detection, attack paths, blast radius, risk
propagation) — each would be a new method on this interface or a dedicated
analytics port consuming the repository.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.graph import (
    GraphEdge,
    GraphNode,
    GraphPath,
    GraphSnapshot,
    NodeType,
    RelationshipType,
)


class IGraphRepository(ABC):
    """Storage-agnostic graph repository contract."""

    # --- mutations -------------------------------------------------------

    @abstractmethod
    def add_node(self, node: GraphNode) -> GraphNode:
        """Add a node, returning the existing node if a duplicate."""

    @abstractmethod
    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Add an edge, suppressing duplicates by key."""

    @abstractmethod
    def update_node_metadata(self, node_id: str, metadata: dict[str, str]) -> None:
        """Merge metadata into an existing node."""

    # --- queries ---------------------------------------------------------

    @abstractmethod
    def get_node(self, node_id: str) -> GraphNode | None:
        """Return a node by ID, or ``None``."""

    @abstractmethod
    def get_edge(self, edge_id: str) -> GraphEdge | None:
        """Return an edge by ID, or ``None``."""

    @abstractmethod
    def neighbors(
        self, node_id: str, *, relationship: RelationshipType | None = None
    ) -> tuple[GraphNode, ...]:
        """Return nodes directly connected to ``node_id``."""

    @abstractmethod
    def edges_of(
        self, node_id: str, *, relationship: RelationshipType | None = None
    ) -> tuple[GraphEdge, ...]:
        """Return edges incident to ``node_id``."""

    @abstractmethod
    def nodes_by_type(self, node_type: NodeType) -> tuple[GraphNode, ...]:
        """Return all nodes of a given type."""

    @abstractmethod
    def shortest_path(self, source_id: str, target_id: str) -> GraphPath:
        """Return the shortest path between two nodes (BFS)."""

    @abstractmethod
    def shared_iocs(self, node_a_id: str, node_b_id: str) -> tuple[GraphNode, ...]:
        """Return IOC nodes reachable from both ``node_a`` and ``node_b``."""

    @abstractmethod
    def subgraph(self, root_id: str, *, max_depth: int = 2) -> tuple[GraphNode, ...]:
        """Return all nodes reachable from ``root_id`` within ``max_depth``."""

    @abstractmethod
    def snapshot(self) -> GraphSnapshot:
        """Return a point-in-time summary of the graph."""

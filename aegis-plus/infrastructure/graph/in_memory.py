"""In-memory graph repository.

A lightweight, dict-backed implementation of :class:`IGraphRepository` suitable
for the current desktop release. The same ``IGraphRepository`` contract will be
satisfied by a future Neo4j, Neptune, or Cosmos DB adapter without changing any
service or query code.

Duplicate suppression uses the deterministic ``key`` property on nodes and edges.
BFS traversal powers ``shortest_path``, ``subgraph``, and ``shared_iocs``.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from core.domain.graph import (
    GraphEdge,
    GraphNode,
    GraphPath,
    GraphSnapshot,
    NodeType,
    RelationshipType,
)
from core.interfaces.graph_repository import IGraphRepository

_MAX_BFS_DEPTH = 10


@dataclass
class InMemoryGraphRepository(IGraphRepository):
    """Dict-backed graph repository with BFS query support."""

    _nodes: dict[str, GraphNode] = field(default_factory=dict)
    _edges: dict[str, GraphEdge] = field(default_factory=dict)
    _edge_keys: dict[str, str] = field(default_factory=dict)
    _adjacency: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    _duplicate_suppressions: int = 0

    # --- mutations -------------------------------------------------------

    def add_node(self, node: GraphNode) -> GraphNode:
        """Add a node, returning the existing one if the key matches."""
        existing = self._nodes.get(node.node_id)
        if existing is not None:
            self._duplicate_suppressions += 1
            return existing
        self._nodes[node.node_id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Add an edge, suppressing duplicates by key."""
        if edge.key in self._edge_keys:
            self._duplicate_suppressions += 1
            return self._edges[self._edge_keys[edge.key]]
        self._edges[edge.edge_id] = edge
        self._edge_keys[edge.key] = edge.edge_id
        self._adjacency[edge.source_id].append(edge.edge_id)
        self._adjacency[edge.target_id].append(edge.edge_id)
        return edge

    def update_node_metadata(self, node_id: str, metadata: dict[str, str]) -> None:
        """Merge metadata into an existing node (creates a new frozen instance)."""
        existing = self._nodes.get(node_id)
        if existing is None:
            return
        merged = {**existing.metadata, **metadata}
        from dataclasses import replace

        self._nodes[node_id] = replace(existing, metadata=merged)

    # --- queries ---------------------------------------------------------

    def get_node(self, node_id: str) -> GraphNode | None:
        """Return a node by ID."""
        return self._nodes.get(node_id)

    def get_edge(self, edge_id: str) -> GraphEdge | None:
        """Return an edge by ID."""
        return self._edges.get(edge_id)

    def neighbors(
        self, node_id: str, *, relationship: RelationshipType | None = None
    ) -> tuple[GraphNode, ...]:
        """Return nodes directly connected to ``node_id``."""
        result: list[GraphNode] = []
        for edge_id in self._adjacency.get(node_id, []):
            edge = self._edges.get(edge_id)
            if edge is None:
                continue
            if relationship is not None and edge.relationship is not relationship:
                continue
            peer_id = edge.target_id if edge.source_id == node_id else edge.source_id
            peer = self._nodes.get(peer_id)
            if peer is not None and peer not in result:
                result.append(peer)
        return tuple(result)

    def edges_of(
        self, node_id: str, *, relationship: RelationshipType | None = None
    ) -> tuple[GraphEdge, ...]:
        """Return edges incident to ``node_id``."""
        result: list[GraphEdge] = []
        for edge_id in self._adjacency.get(node_id, []):
            edge = self._edges.get(edge_id)
            if edge is None:
                continue
            if relationship is not None and edge.relationship is not relationship:
                continue
            result.append(edge)
        return tuple(result)

    def nodes_by_type(self, node_type: NodeType) -> tuple[GraphNode, ...]:
        """Return all nodes of a given type."""
        return tuple(n for n in self._nodes.values() if n.node_type is node_type)

    def shortest_path(self, source_id: str, target_id: str) -> GraphPath:
        """BFS shortest path between two nodes."""
        if source_id == target_id:
            node = self._nodes.get(source_id)
            return GraphPath(nodes=(node,) if node else (), edges=())
        visited: set[str] = {source_id}
        queue: deque[tuple[str, list[str], list[str]]] = deque()
        queue.append((source_id, [source_id], []))
        while queue:
            current, node_path, edge_path = queue.popleft()
            if len(node_path) > _MAX_BFS_DEPTH:
                break
            for edge_id in self._adjacency.get(current, []):
                edge = self._edges.get(edge_id)
                if edge is None:
                    continue
                peer = edge.target_id if edge.source_id == current else edge.source_id
                if peer in visited:
                    continue
                visited.add(peer)
                new_nodes = [*node_path, peer]
                new_edges = [*edge_path, edge_id]
                if peer == target_id:
                    return GraphPath(
                        nodes=tuple(self._nodes[nid] for nid in new_nodes if nid in self._nodes),
                        edges=tuple(self._edges[eid] for eid in new_edges if eid in self._edges),
                    )
                queue.append((peer, new_nodes, new_edges))
        return GraphPath()

    def shared_iocs(self, node_a_id: str, node_b_id: str) -> tuple[GraphNode, ...]:
        """Return IOC nodes reachable from both nodes."""
        iocs_a = {
            n.node_id for n in self.subgraph(node_a_id, max_depth=2) if n.node_type is NodeType.IOC
        }
        iocs_b = {
            n.node_id for n in self.subgraph(node_b_id, max_depth=2) if n.node_type is NodeType.IOC
        }
        shared = iocs_a & iocs_b
        return tuple(self._nodes[nid] for nid in shared if nid in self._nodes)

    def subgraph(self, root_id: str, *, max_depth: int = 2) -> tuple[GraphNode, ...]:
        """BFS subgraph reachable from ``root_id`` within ``max_depth``."""
        visited: set[str] = {root_id}
        queue: deque[tuple[str, int]] = deque([(root_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge_id in self._adjacency.get(current, []):
                edge = self._edges.get(edge_id)
                if edge is None:
                    continue
                peer = edge.target_id if edge.source_id == current else edge.source_id
                if peer not in visited:
                    visited.add(peer)
                    queue.append((peer, depth + 1))
        return tuple(self._nodes[nid] for nid in visited if nid in self._nodes)

    def snapshot(self) -> GraphSnapshot:
        """Point-in-time graph summary."""
        node_counts: dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            node_counts[node.node_type.value] += 1
        edge_counts: dict[str, int] = defaultdict(int)
        for edge in self._edges.values():
            edge_counts[edge.relationship.value] += 1
        return GraphSnapshot(
            node_count=len(self._nodes),
            edge_count=len(self._edges),
            node_type_counts=dict(node_counts),
            relationship_type_counts=dict(edge_counts),
            duplicate_suppressions=self._duplicate_suppressions,
        )

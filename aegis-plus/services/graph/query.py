"""Graph Query Service.

Reusable, storage-agnostic query capabilities for the knowledge graph. Every
method delegates to the :class:`IGraphRepository` port, so the same service
works with the in-memory implementation now and Neo4j/Neptune later.

The service also exposes extension points for future analytics (centrality,
components, community detection, attack paths, blast radius, risk propagation)
as methods that currently return empty results but carry the correct signatures.
"""

from __future__ import annotations

from core.domain.graph import (
    GraphEdge,
    GraphNode,
    GraphPath,
    GraphSnapshot,
    NodeType,
    RelationshipType,
)
from core.interfaces.graph_repository import IGraphRepository

_MAX_DEPTH = 3
_COMPONENT_DEPTH = 10_000


class GraphQueryService:
    """High-level query interface for the knowledge graph."""

    def __init__(self, repository: IGraphRepository) -> None:
        """Initialize the query service.

        Args:
            repository: The graph repository to query.
        """
        self._repo = repository

    def lookup(self, node_id: str) -> GraphNode | None:
        """Return a node by ID, or ``None``."""
        return self._repo.get_node(node_id)

    def neighbors(
        self, node_id: str, *, relationship: RelationshipType | None = None
    ) -> tuple[GraphNode, ...]:
        """Return nodes directly connected to ``node_id``."""
        return self._repo.neighbors(node_id, relationship=relationship)

    def edges_of(
        self, node_id: str, *, relationship: RelationshipType | None = None
    ) -> tuple[GraphEdge, ...]:
        """Return edges incident to ``node_id``."""
        return self._repo.edges_of(node_id, relationship=relationship)

    def related_artifacts(self, artifact_id: str) -> tuple[GraphNode, ...]:
        """Return artifact nodes related to ``artifact_id``."""
        return tuple(
            n
            for n in self._repo.neighbors(artifact_id)
            if n.node_type in (NodeType.FILE, NodeType.URL, NodeType.EMAIL, NodeType.ARTIFACT)
        )

    def shared_iocs(self, node_a: str, node_b: str) -> tuple[GraphNode, ...]:
        """Return IOC nodes reachable from both nodes."""
        return self._repo.shared_iocs(node_a, node_b)

    def incident_relationships(self, incident_id: str) -> tuple[GraphEdge, ...]:
        """Return all edges incident to an incident node."""
        return self._repo.edges_of(incident_id)

    def campaign_relationships(self, campaign_id: str) -> tuple[GraphEdge, ...]:
        """Return all edges incident to a campaign node."""
        return self._repo.edges_of(campaign_id)

    def investigation_subgraph(self, root_id: str, *, max_depth: int = 2) -> tuple[GraphNode, ...]:
        """Return the subgraph reachable from an investigation root."""
        return self._repo.subgraph(root_id, max_depth=max_depth)

    def shortest_path(self, source_id: str, target_id: str) -> GraphPath:
        """BFS shortest path between two nodes."""
        return self._repo.shortest_path(source_id, target_id)

    def reachable(self, node_id: str, *, max_depth: int = 3) -> tuple[GraphNode, ...]:
        """Return all nodes reachable within ``max_depth`` hops."""
        return self._repo.subgraph(node_id, max_depth=max_depth)

    def all_nodes(self) -> tuple[GraphNode, ...]:
        """Every node in the graph, across all types (enumeration primitive)."""
        collected: list[GraphNode] = []
        for node_type in NodeType:
            collected.extend(self._repo.nodes_by_type(node_type))
        return tuple(collected)

    def snapshot(self) -> GraphSnapshot:
        """Point-in-time graph summary."""
        return self._repo.snapshot()

    # --- lightweight analytics (extension points) ------------------------

    def centrality(self, node_id: str) -> float:
        """Degree centrality of a node, normalized to ``[0, 1]``.

        A lightweight, O(degree) proxy for importance: a node's edge count
        divided by the maximum possible connections ``(N - 1)``. Heavier measures
        (betweenness, eigenvector) are intentionally out of scope.
        """
        total = self._repo.snapshot().node_count
        if total <= 1:
            return 0.0
        return len(self._repo.edges_of(node_id)) / (total - 1)

    def connected_components(self) -> tuple[tuple[str, ...], ...]:
        """Connected components as tuples of node ids.

        A single linear pass over the graph using the repository's BFS
        (``neighbors``); each unvisited node seeds a component. O(N + E) — within
        the intended lightweight scope.
        """
        components: list[tuple[str, ...]] = []
        visited: set[str] = set()
        for node in self._all_nodes():
            if node.node_id in visited:
                continue
            reached = {node.node_id}
            reached.update(
                n.node_id for n in self.reachable(node.node_id, max_depth=_COMPONENT_DEPTH)
            )
            visited |= reached
            components.append(tuple(sorted(reached)))
        return tuple(components)

    def communities(self) -> tuple[tuple[str, ...], ...]:
        """Community detection — intentionally not implemented (out of scope).

        Modularity-based detection is computationally heavy; the Explorer relies
        on connected components for its lightweight grouping instead.
        """
        return ()

    def attack_paths(self, source_id: str, target_id: str) -> tuple[GraphPath, ...]:
        """Candidate attack path(s) between two nodes (lightweight).

        Returns the single shortest path when one exists, rather than
        enumerating all simple paths (which is exponential and out of scope).
        """
        path = self.shortest_path(source_id, target_id)
        return () if path.is_empty else (path,)

    def blast_radius(self, node_id: str) -> tuple[GraphNode, ...]:
        """Nodes reachable from ``node_id`` (its blast radius)."""
        return self.reachable(node_id, max_depth=_MAX_DEPTH)

    def graph_density(self) -> float:
        """Undirected graph density ``2E / (N(N-1))`` in ``[0, 1]``.

        Zero for graphs with fewer than two nodes. A cheap structural measure of
        how interconnected the graph is.
        """
        snap = self._repo.snapshot()
        n = snap.node_count
        if n <= 1:
            return 0.0
        return (2 * snap.edge_count) / (n * (n - 1))

    def _all_nodes(self) -> tuple[GraphNode, ...]:
        """Enumerate every node across all types via the repository port."""
        collected: list[GraphNode] = []
        for node_type in NodeType:
            collected.extend(self._repo.nodes_by_type(node_type))
        return tuple(collected)

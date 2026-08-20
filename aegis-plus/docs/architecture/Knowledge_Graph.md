# Knowledge Graph

**Status:** Current (M9 Phases 1–3)
**Domain:** `core/domain/graph.py` · **Port:** `core/interfaces/graph_repository.py`
· **Adapter:** `infrastructure/graph/in_memory.py` · **Build/query:** `services/graph/`

The knowledge graph is a platform capability that links intelligence entities
(artifacts, threats, incidents, campaigns, IOCs, providers, and more) so they can
be traversed, correlated, and explored.

## 1. Domain

- **`GraphNode`** — `node_id`, `node_type` (`NodeType`, 13 values:
  artifact/url/domain/file/email/hash/ioc/threat/incident/campaign/investigation/
  provider/ip_address), `display_name`, `labels`, `metadata` (carries verdict,
  risk_score, etc.).
- **`GraphEdge`** — `edge_id`, `source_id`, `target_id`, `relationship`
  (`RelationshipType`, 13 values incl. contains, shares_ioc, related_to,
  observed_in, associated_with, analyzed_by, member_of), `confidence`,
  `provenance`, `timestamp`.
- **`GraphPath`**, **`GraphSnapshot`** (counts, node/relationship type counts,
  duplicate suppressions).

## 2. Port & adapter

`IGraphRepository` is Core-owned and storage-agnostic (add_node/add_edge/
update_node_metadata/get_node/get_edge/neighbors/edges_of/nodes_by_type/
shortest_path/shared_iocs/subgraph/snapshot). The current adapter,
`InMemoryGraphRepository`, is dict-backed with BFS traversal, deterministic
deduplication by key, and an adjacency index. The port is replaceable with
Neo4j/Neptune/JanusGraph/Cosmos DB **without changing callers** — persistence is
a future milestone (M10) and the interface is intentionally not modified to
anticipate it.

## 3. Build

`GraphBuilder` subscribes to intelligence events on the internal bus and creates
nodes/edges automatically; publishers remain unaware of the graph (see
[Event Bus Interaction](Event_Bus_Interaction.md)). As of M10 the detection and
investigation services publish these events through the `IntelligencePublisher`
seam, so the graph populates live as artifacts are analysed. See
[Live Intelligence Pipeline](Live_Intelligence_Pipeline.md).

## 4. Query & analytics

`GraphQueryService` provides traversal (lookup, neighbors, edges_of,
related_artifacts, shared_iocs, investigation_subgraph, shortest_path, reachable,
snapshot) and **lightweight analytics**:

| Method | Meaning | Cost |
|--------|---------|------|
| `centrality(id)` | Degree centrality, normalized to `[0,1]` | O(degree) |
| `connected_components()` | Components as node-id tuples (single BFS pass) | O(N+E) |
| `graph_density()` | `2E / (N(N-1))` | O(1) |
| `blast_radius(id)` | Reachable set within depth | O(reachable) |
| `attack_paths(a,b)` | Shortest path only (not full enumeration) | O(BFS) |
| `communities()` | Not implemented — out of lightweight scope | — |

Heavier measures (betweenness/eigenvector centrality, community detection, full
path enumeration) are intentionally excluded.

## 5. Exploration overview

`GraphExplorerService` builds on the query service to produce bounded,
presentation-ready views and an analytics summary (entity/relationship
distribution, most-connected entities, component count, largest component,
density, blast-radius/reachability). See
[Graph Explorer Architecture](Graph_Explorer_Architecture.md).

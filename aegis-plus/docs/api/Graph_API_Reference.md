# Graph API Reference — `/api/graph/*`

**Status:** Current (M9 Phase 3-C)
**Router:** `application/api/graph.py` · **Service:** `GraphExplorerService`

All endpoints return presentation view DTOs (JSON) reconstructed UI-side by
`BackendClient`. All are read-only `GET` requests. The graph is populated by the
`GraphBuilder` from intelligence events; as of M10 the detection and investigation
services publish these events, so the graph populates live during analysis.

## Endpoints

| Method & path | Purpose | Notes |
|---------------|---------|-------|
| `GET /api/graph/snapshot` | Whole-graph counts + type distributions | — |
| `GET /api/graph/analytics?top=N` | Lightweight analytics summary | `top` caps most-connected list |
| `GET /api/graph/search?q=…&limit=N` | Search nodes by id/label/metadata | `422` if `q` empty; auto-focus on first match |
| `GET /api/graph/path?source=…&target=…` | Shortest path between two nodes | `found=false` when none |
| `GET /api/graph/shared-iocs?a=…&b=…` | IOCs common to two nodes as a view | — |
| `GET /api/graph/investigation/{root_id}?depth=N` | Investigation subgraph | empty view if root absent |
| `GET /api/graph/incident/{incident_id}` | Incident neighbourhood | — |
| `GET /api/graph/campaign/{campaign_id}` | Campaign neighbourhood | — |
| `GET /api/graph/nodes/{node_id}` | Single node view | `404` if absent |
| `GET /api/graph/nodes/{node_id}/neighbors?depth=N` | Node + neighbourhood view | — |
| `GET /api/graph/nodes/{node_id}/selection` | Focus + neighbour/edge id sets | — |

## Key response shapes

### Node view
```json
{ "node_id": "url-1", "node_type": "url", "label": "http://…",
  "tone": "danger", "risk_percent": 90, "degree": 3,
  "labels": ["phishing"], "metadata": {"risk_score": "0.9"} }
```

### Graph view
```json
{ "root_id": "url-1", "truncated": false,
  "nodes": [ …node views… ],
  "edges": [ { "edge_id": "e1", "source_id": "url-1", "target_id": "ioc-1",
               "relationship": "shares_ioc", "confidence": 0.8,
               "provenance": "ioc-fusion", "timestamp": "2026-01-01T00:00" } ] }
```
Views are bounded to 250 nodes; `truncated` is `true` when the cap is hit.

### Analytics summary (P3-C)
```json
{ "node_count": 6, "edge_count": 7, "ioc_count": 1,
  "node_type_counts": [["incident",1],["ioc",1],["url",1]],
  "relationship_type_counts": [["shares_ioc",2],["observed_in",1]],
  "most_connected": [ { "node": {…node view…}, "degree": 4 } ],
  "largest_component_size": 6, "component_count": 1,
  "reachable_from_top": 6, "density": 0.4667 }
```
`relationship_type_counts`, `component_count`, and `density` were added in P3-C
(additive; older clients default them safely).

## Error semantics

- `404` — node lookup for a missing node.
- `422` — empty search query.
- Graph-of endpoints (investigation/incident/campaign) return an **empty view**
  (not an error) when the root is absent.

## Client gateway

`BackendClient` exposes one method per endpoint (`graph_snapshot`,
`graph_analytics`, `graph_search`, `graph_shortest_path`, `graph_shared_iocs`,
`graph_investigation`, `graph_incident`, `graph_campaign`, `graph_node`,
`graph_neighbors`, `graph_selection`) returning the reconstructed Core view DTOs,
with safe defaults on transport error.

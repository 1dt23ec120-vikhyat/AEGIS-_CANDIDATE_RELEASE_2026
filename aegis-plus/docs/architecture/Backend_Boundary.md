# Graph Explorer — Backend Boundary

**Status:** Current (M9 Phase 3-C)

This note defines the boundary between the Intelligence Graph Explorer UI and the
backend, and the observability exposed at that boundary.

## 1. The boundary

The UI communicates with the backend **only** over HTTP through `BackendClient`.
It never imports `services`, the graph repository, or domain graph objects. This
is enforced by the Import Linter contract *"UI depends on Core only; reaches
services over HTTP, not by import"* (7/7 contracts kept).

```
UI  ──HTTP──▶  /api/graph/*  ──▶  GraphExplorerService  ──▶  GraphQueryService  ──▶  IGraphRepository
```

Only pure view DTOs (`core/domain/graph_view.py`) cross the boundary. The service
maps domain graph objects to these DTOs; the client reconstructs them from JSON.

## 2. Contract stability

The REST surface and view DTOs are the contract. DTO fields are **additive** with
defaults, so older clients keep working (e.g. the P3-C analytics fields
`relationship_type_counts`, `component_count`, `density` were added without
breaking existing consumers). See [Graph API Reference](../api/Graph_API_Reference.md).

## 3. Observability at the boundary

`GraphExplorerService` records the wall-clock duration of each leaf query (via an
internal `@_tracked` decorator that avoids double-counting delegations) and
exposes:

```python
GraphExplorerService.metrics() -> {
    "query_count":   float,   # number of graph queries served
    "total_query_ms": float,  # cumulative duration
    "avg_query_ms":   float,  # mean duration
}
```

These are surfaced through the existing health infrastructure as the
`graph-explorer` health component (alongside `knowledge-graph` and `event-bus`),
reusing the `HealthComponent` pattern. The UI additionally measures and displays
presentation-side timings (layout, render, expansion, search, timeline filtering)
in the Analytics panel.

## 4. What the boundary deliberately excludes

- No persistence or caching layer sits behind the boundary in this milestone.
- The service is **stateless** with respect to analyst sessions; session state is
  held in the UI (in-memory) only.
- As of M10, detection services publish intelligence events, so the graph
  populates live during analysis workflows (see
  [Live Intelligence Pipeline](Live_Intelligence_Pipeline.md)).

# Intelligence Graph Explorer — Architecture

**Status:** Current (M9 Phase 3-C)
**Layers:** Core (view DTOs) · Services (query/explorer) · Application (REST) · UI (MVVM)

The Intelligence Graph Explorer lets analysts explore the knowledge graph —
pivoting across entities, tracing attack paths, filtering, and reviewing
analytics. It is layered strictly per Clean Architecture; the presentation layer
never touches the graph repository or domain graph objects.

## 1. Layered structure

```
GraphExplorerPage (view)                     ui/pages/
        │  Qt signals
GraphExplorerViewModel (state + orchestration)  ui/viewmodels/
        │  HTTP (BackendClient)
/api/graph/* (REST router)                    application/api/graph.py
        │
GraphExplorerService (application service)    services/graph/explorer.py
        │  delegates
GraphQueryService (traversal/query)           services/graph/query.py
        │  port
IGraphRepository  ← InMemoryGraphRepository   core/interfaces, infrastructure/graph
```

Shared presentation contracts (`core/domain/graph_view.py`) are pure, frozen
view DTOs used by both the producer (service/API) and the consumer (UI gateway),
following the same precedent as `InvestigationSummary`.

## 2. Responsibilities

| Component | Responsibility |
|-----------|----------------|
| `GraphQueryService` | Storage-agnostic traversal/query + lightweight analytics (centrality, connected components, density, blast radius, attack paths). Delegates to `IGraphRepository`. |
| `GraphExplorerService` | Maps domain graph → view DTOs; derives display tone/risk; bounds views (`_MAX_VIEW_NODES = 250`, `truncated`); aggregates analytics; tracks backend query metrics. Reimplements no traversal. |
| `/api/graph/*` | Thin REST surface returning presentation DTOs only. |
| `BackendClient` | UI-side gateway; reconstructs view DTOs from JSON; safe defaults on error. |
| `GraphExplorerViewModel` | Owns loaded graph, filters, timeline cutoff, selection, session state; runs backend calls off the UI thread; client-side filtering/timeline; observability metrics. |
| `GraphExplorerPage` | Thin view: composes canvas + toolbar + panels; wires widgets to view-model signals. |

## 3. MVVM & threading

The view-model performs all backend access through an injectable
**runner factory** (`RunnerFactory`, default `AsyncRunner`) so calls run off the
UI thread. Tests inject a synchronous runner for deterministic execution. The
view (page) holds no business logic; it renders view-model signals and forwards
user intents.

## 4. Client-side filtering & timeline

Loading replaces the view-model's `current_view`. Filters (node type,
relationship type, confidence) and the timeline cutoff are applied **client-side**
by computing visible node/edge id sets and emitting `visibility_changed`; the
canvas dims what is filtered out without re-fetching. This keeps interaction
latency low and the backend stateless.

## 5. Observability

Presentation timings (layout, render, expansion, search, timeline filtering,
backend query duration) and counts (nodes, edges, visible/hidden, expansions,
depth) are accumulated by the view-model and surfaced in the Analytics panel.
Backend query duration is additionally tracked by `GraphExplorerService.metrics()`
and exposed through the `graph-explorer` health component. See
[Backend Boundary](Backend_Boundary.md).

## 6. Session state (in-memory)

`ExplorerSessionState` / `ViewportState` (in `ui/viewmodels/explorer_session.py`)
capture focus, expanded nodes, filters, timeline position, expansion depth, and
viewport. They are **in-memory only**; the capture/restore surface exists so a
future milestone (M10) can add persistence without reshaping the presentation
layer. No storage is read or written today.

## 7. Investigation integration

The File Investigation workspace offers "Open in Graph Explorer", which navigates
to the Explorer focused on the artifact via payload-aware navigation
(`Router.navigate(route, payload)` → the page's `on_navigated` hook). The Explorer
offers "Back to investigation". No investigation logic is duplicated.

## 8. Constraints honoured

- No persistence layer; in-memory adapters only.
- Repository interfaces unchanged.
- As of M10, detection and investigation services publish intelligence events
  through the `IntelligencePublisher` seam, so the graph populates live; the
  Explorer reflects newly analysed intelligence. See
  [Live Intelligence Pipeline](Live_Intelligence_Pipeline.md).

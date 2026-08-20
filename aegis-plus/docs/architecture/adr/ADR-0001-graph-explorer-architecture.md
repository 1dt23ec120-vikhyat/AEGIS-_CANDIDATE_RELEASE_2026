# ADR-0001 — Intelligence Graph Explorer Architecture

- **Status:** Accepted (M9 Phase 3; finalised in P3-C)
- **Context date:** M9
- **Deciders:** Architecture review (gated milestone approvals)

## Context

AEGIS+ needed an analyst-facing way to explore the knowledge graph — pivoting
across entities, tracing attack paths, filtering, and reviewing analytics —
without violating Clean Architecture or coupling the UI to the graph internals.
The knowledge graph, event bus, and in-memory repository already existed
(M9 P1/P2). Persistence is explicitly deferred to a future milestone (M10).

## Decision

1. **Presentation view DTOs in Core.** Pure, frozen graph view DTOs
   (`core/domain/graph_view.py`) are shared by the producer (service/API) and the
   consumer (UI gateway), mirroring the `InvestigationSummary` precedent.
2. **A dedicated application service** (`GraphExplorerService`) orchestrates the
   frozen `GraphQueryService` and reuses `IGraphRepository` for enumeration. It
   maps domain→view DTOs, bounds views, aggregates analytics, and tracks query
   metrics. It reimplements no traversal.
3. **REST + BackendClient boundary.** The UI reaches the service only over HTTP
   through `BackendClient`; it never imports services or domain graph objects.
   Enforced by Import Linter.
4. **MVVM with an injectable runner.** `GraphExplorerViewModel` owns state and
   orchestration; an injectable `RunnerFactory` (default `AsyncRunner`) runs
   backend calls off the UI thread and enables synchronous, deterministic tests.
5. **Client-side filtering/timeline.** Filters and the timeline cutoff are applied
   in the UI over the loaded view, keeping the backend stateless and interactions
   fast.
6. **Payload-aware navigation.** `Router.navigate(route, payload)` gained an
   optional payload delivered to a page's `on_navigated` hook, enabling deep links
   (e.g. open the Explorer focused on an artifact) with full backward
   compatibility.
7. **In-memory session state.** `ExplorerSessionState`/`ViewportState` define a
   capture/restore surface with no persistence, so M10 can add durability without
   reshaping the presentation layer.

## Consequences

**Positive**

- Strict layering; 7/7 Import Linter contracts kept.
- The graph backend (repository, query service, bus) is reused unchanged.
- Additive DTO evolution (P3-C analytics fields) without breaking clients.
- The persistence swap (Neo4j/Neptune/…) is isolated behind `IGraphRepository`.

**Negative / accepted trade-offs**

- Client-side filtering assumes bounded views (cap 250 nodes, `truncated`).
- The live graph is empty until detection services publish events (deferred).
- The injectable runner adds a small constructor parameter to the view-model and
  page (defaulted; production behaviour unchanged).

## Alternatives considered

- **UI calls the service directly** — rejected: violates the UI→Core-only
  contract and couples presentation to internals.
- **Server-side filtering/session state** — deferred: unnecessary for current
  scale and would add stateful endpoints ahead of the persistence milestone.
- **Full graph analytics (community detection, betweenness)** — rejected as out
  of the intended lightweight scope.

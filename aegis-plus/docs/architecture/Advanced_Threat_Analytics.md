# Advanced Threat Analytics & Intelligence Engine

**Status:** Current (M11)
**Package:** `services/analytics/` · **DTOs:** `core/domain/{analytics,intelligence,attack,recommendation,soc_analytics}_view.py`
· **API:** `application/api/analytics.py` · **UI:** SOC dashboard + Graph Explorer overlay

M11 turns the live intelligence platform into an intelligence-driven analytics
engine. Every capability is **deterministic** and **composes existing services**
(graph query, graph builder, event bus, fusion, correlation) — it reimplements no
graph algorithm, introduces no persistence, and changes no repository interface.

## 1. Layering

```
SOC dashboard / Graph Explorer (UI, MVVM)
        │  BackendClient (HTTP)
/api/analytics/{overview,overlay}          application/api/analytics.py
        │
AnalyticsOverviewService · GraphOverlayService          (Phase E aggregation)
        │
RecommendationService                                   (Phase D)
        │
IOC / Campaign / ThreatScoring / AttackAnalysis         (Phase B/C)
        │
GraphAnalyticsService                                   (Phase A)
        │
GraphQueryService ─▶ IGraphRepository (in-memory)
```

All analytics DTOs live in `core/domain` as frozen, framework-free value objects,
following the graph-view precedent. Each scoring/analysis DTO carries a
`rationale` — the plain-language *why*.

## 2. Phase A — Graph Analytics Engine

`GraphAnalyticsService` composes `GraphQueryService` into deterministic analytics:
node degree, centrality ranking, connected-component analysis, relationship
density, blast-radius estimation, reachability, shortest attack paths, multi-hop
neighbourhood, shared-infrastructure discovery (origin → infra → peer), and
threat propagation. Rankings are ordered by score then id for stable output.

## 3. Phase B — Threat Intelligence Engine

- **IOC intelligence:** frequency, prevalence, reuse, confidence (weighted from
  edge confidence, reuse breadth, and connected-artifact risk), and aging from
  edge timestamps.
- **Campaign intelligence:** artifact/IOC/infrastructure counts, evolution span,
  and pairwise Jaccard similarity over shared infrastructure.
- **Threat scoring:** severity, exposure (reusing Phase A blast radius),
  confidence, priority, and analyst urgency, each explained.

## 4. Phase C — Attack Analysis Engine

`AttackAnalysisService` reconstructs attack chains (shortest path with kill-chain
phases), maps nodes to Lockheed-Martin kill-chain phases (deterministic node-type
mapping), discovers compromise paths and infrastructure clusters, infers incident
root causes (earliest artifact), reports threat propagation (reusing Phase A), and
reconstructs time-ordered attack timelines.

## 5. Phase D — Analyst Recommendation Engine

`RecommendationService` selects subjects using the Phase A–C services' own scores
and carries their rationale forward — next investigation, highest-priority IOC,
highest-risk campaign, most-suspicious relationship, suggested containment order,
and investigation sequence. No scoring logic is duplicated here.

## 6. Phase E — SOC & Graph Explorer extensions

- **`AnalyticsOverviewService`** aggregates Phases B–D into dashboard widgets
  (threat priorities, emerging campaigns, IOC trends, infrastructure reuse,
  critical attack paths, threat distribution, recommendations), exposed at
  `GET /api/analytics/overview`.
- **`GraphOverlayService`** annotates every node (risk, critical, campaign,
  cluster, attack-path, propagation rank), exposed at `GET /api/analytics/overlay`.
- **SOC dashboard:** an additive "Advanced Threat Analytics" section, fetched via
  a second async request — the existing dashboard flow is untouched.
- **Graph Explorer:** an "Analytics Overlay" toggle that highlights critical nodes
  and attack paths, reusing the canvas's existing `highlight_nodes` mechanism —
  the Explorer is not redesigned.

## 7. Observability

Every service extends `MeteredService` (`services/analytics/observability.py`),
exposing a uniform `metrics()` (runs, durations, per-operation counts) via a
shared `tracked` decorator — no timing logic is duplicated. The container surfaces
a `graph-analytics` health component and an aggregate `intelligence-engine`
component (IOC, campaign, scoring, attack, recommendations, overview, overlay).

## 8. Constraints honoured

No redesign of the Event Bus, Knowledge Graph, Graph Builder, Query Service,
Analytics, fusion, correlation, or Explorer; no persistence; no database; no
repository changes; no duplicated algorithms. All 7 Import Linter contracts hold.

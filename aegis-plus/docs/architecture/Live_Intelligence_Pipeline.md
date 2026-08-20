# Live Intelligence Pipeline

**Status:** Current (M10)
**Seam:** `services/pipeline/publisher.py::IntelligencePublisher`
**Consumers:** `GraphBuilder`, `EventHistory` (already subscribed)

The live intelligence pipeline makes AEGIS+ event-driven end to end: when a
detection service finishes analysing an artifact, it publishes intelligence
events onto the internal bus, where the subscribed `GraphBuilder` populates the
knowledge graph and `EventHistory` records the activity. The Intelligence Graph
Explorer therefore reflects newly analysed intelligence with no additional wiring.

No persistence, no database technology, and no repository-interface change were
introduced; the bus, builder, graph, and Explorer are reused as-is.

## 1. Flow

```
UrlAnalysisService.analyze()  ─┐
EmailAnalysisService.analyze() ─┤ extract facts
FileAnalysisService.analyze()  ─┘        │
                                         ▼
                        IntelligencePublisher  (single seam — all event construction)
                                         │ publish
                                         ▼
                                InProcessEventBus
                                   │            │
                                   ▼            ▼
                             GraphBuilder   EventHistory
                                   │
                                   ▼
                            IGraphRepository  →  Graph Explorer reflects it
```

## 2. The single publishing seam

To avoid duplicating publisher logic across the three detection services, **all**
event construction lives in `IntelligencePublisher`. Each service extracts its
facts and calls one method:

- `analysis_completed(...)` — emits `artifact_analyzed` always; `ioc_extracted`
  when IOCs are reported (enumerated `iocs` or a bare `ioc_count`) plus one
  `relationship_discovered` (`shares_ioc`) per enumerated IOC; a
  `relationship_discovered` per `related` entry; and `threat_recorded` when the
  verdict is malicious.
- `incident_opened(...)`, `campaign_observed(...)` — published by the email and
  file services when their existing correlation opens an incident/campaign.
- `investigation_recorded(...)` — published by the investigation services on save.

Publishing is **best-effort**: `IntelligencePublisher._emit` isolates failures
(counted and logged) so a publishing problem can never break an analysis result.

## 3. What each service publishes

| Service | artifact_id | IOCs / relationships | Extra |
|---------|-------------|----------------------|-------|
| URL analysis | scan URL | host as IOC | `threat_recorded` if malicious |
| Email analysis | email identity | sender domain (IOC); embedded URLs (`contains`) | incident + campaign on correlation |
| File analysis | SHA-256 | indicator count; embedded URLs (`contains`) | incident + campaign on correlation |
| Email/File investigation | — | — | `investigation_completed` on save |

The `GraphBuilder` already subscribes to exactly these event types, so **no
builder change was required** — publishers emit only what the builder consumes.

## 4. Composition

The dependency container builds the event bus, knowledge graph, and the
`IntelligencePublisher` **before** the detection services, then injects the
publisher into each. The publisher parameter is optional (defaults to `None`), so
constructing a service without it — as much of the test suite does — simply
publishes nothing. This preserves full backward compatibility.

## 5. Observability

The pipeline is monitored through the existing health infrastructure
(`SocOverviewService` health components):

| Component | Surfaces |
|-----------|----------|
| `event-bus` | subscribers, events published, dispatched, failures |
| `graph-builder` | graph updates (build count) and total processing time |
| `intelligence-publisher` | events published and publish failures (degraded if any) |

`IntelligencePublisher.metrics()` additionally exposes per-type counts. Together
these cover event publication, event processing, graph updates, processing
latency, and publisher health.

## 6. Constraints honoured

- No persistence and no database technology introduced.
- `IGraphRepository` and all repository contracts unchanged; in-memory adapters
  intact.
- Event bus, `GraphBuilder`, `GraphQueryService`, and the Explorer reused without
  redesign; no duplicated publisher logic.
- All seven Import Linter contracts kept (intra-services import of
  `services.pipeline` by the detection services is inward/sideways within the
  services layer, not a dependency on delivery or adapters).

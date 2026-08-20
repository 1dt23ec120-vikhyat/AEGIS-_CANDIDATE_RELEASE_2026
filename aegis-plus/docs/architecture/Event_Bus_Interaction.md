# Internal Event Bus — Interaction Notes

**Status:** Current (M9 Phase 1+)
**Port:** `core/interfaces/event_bus.py` · **Impl:** `services/events/`

The internal event bus decouples intelligence producers from downstream
consumers (graph building, history) via in-process, synchronous publish/subscribe.

## 1. Contract

- **`IEventBus`** — `publish`, `subscribe`, `subscriber_count`.
- **`IntelligenceEvent`** — frozen value object: `event_id`, `event_type`
  (`EventType`, 14 values), `timestamp`, `correlation_id`, `source`,
  `artifact_id`, `payload`. Convenience constructors: `artifact_analyzed`,
  `threat_recorded`, `incident_created`/`updated`, `campaign_created`/`updated`,
  `relationship_discovered`, and others.
- **`InProcessEventBus`** — ordered delivery, failure isolation (a failing
  handler is logged but does not block others), per-publish/per-handler timing,
  and accumulated `metrics`.
- **`EventHistory`** — bounded in-memory ring buffer for recent events.

## 2. Graph interaction

`GraphBuilder.attach(bus)` subscribes to the relevant event types
(`ARTIFACT_ANALYZED`, `THREAT_RECORDED`, `INCIDENT_*`, `CAMPAIGN_*`,
`RELATIONSHIP_DISCOVERED`, `PROVIDER_COMPLETED`, `IOC_EXTRACTED`). On each event
it creates/updates graph nodes and edges. **Publishers never reference the
graph** — they publish events; the builder reacts. This is the seam that lets the
graph grow without coupling detection code to it.

```
detection service ──publish──▶ InProcessEventBus ──▶ GraphBuilder ──▶ IGraphRepository
                                                └──▶ EventHistory
```

## 3. Live population (M10)

As of M10, the detection services (URL/email/file analysis) publish intelligence
events through the single `IntelligencePublisher` seam when they complete an
analysis, and the investigation services publish on save. The `GraphBuilder`
consumes them and the knowledge graph populates live. Publishers never reference
the graph — they publish events; the builder reacts. See
[Live Intelligence Pipeline](Live_Intelligence_Pipeline.md).

## 4. Observability

`InProcessEventBus.metrics` reports totals (published/dispatched/failures),
publish duration, and per-type counts. The container surfaces bus health as the
`event-bus` component (subscriber count).

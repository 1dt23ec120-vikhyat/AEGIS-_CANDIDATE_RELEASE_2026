# Roadmap

This roadmap summarises delivered milestones and the planned direction. It is a
companion to `PROJECT_PROGRESS.md` (detailed status) and `CHANGELOG.md`.

## Delivered

- **M1–M3** — Platform foundation, walking skeleton, and the first detection
  vertical.
- **M4 — URL Intelligence Engine** — LightGBM analyzer behind `IUrlAnalyzer` with
  heuristic fallback, SHAP explanations, offline domain intelligence, XAI panel.
- **M5 — Email Threat Intelligence Engine** — stdlib parsing, hybrid analyzer,
  SOC investigation console.
- **M6 — Incident Intelligence & Campaign Correlation** — correlation service,
  campaign/incident aggregates, timeline.
- **M7 — SOC Command Center** — single-snapshot aggregation, premium dashboard.
- **M9 P1 — Internal Intelligence Event Bus.**
- **M9 P2 — Knowledge Graph Domain** (port + in-memory adapter + builder + query).
- **M9 P3.0 — Baseline Architecture Remediation** (7/7 contracts).
- **M9 P3-A — Graph Explorer Application Layer** (service, API, DTOs, gateway).
- **M9 P3-B — Intelligence Graph Explorer** (MVVM presentation layer).
- **M9 P3-C — Graph Explorer Hardening, Observability & Release**: lightweight
  analytics, observability, session-prep structures, polish, and complete
  documentation.
- **M10 — Live Intelligence Pipeline**: detection and investigation services
  publish intelligence events through the single `IntelligencePublisher` seam;
  the subscribed `GraphBuilder` populates the knowledge graph live and the Graph
  Explorer reflects newly analysed intelligence. Enriched pipeline observability.
  No persistence, no repository-interface change.
- **M11 — Advanced Threat Analytics & Intelligence Engine**: deterministic,
  explainable graph analytics, IOC/campaign/threat intelligence, attack analysis
  (chains, kill-chain mapping, compromise paths, root cause, clusters, timelines),
  analyst recommendations, and SOC dashboard + Graph Explorer analytics
  extensions — all composed over the existing services. No persistence, no
  redesign, no duplicated algorithms.
- **M12 Phase 1 — AI Security Copilot (Reasoning Engine)**: a read-only,
  natural-language interpretive layer over the deterministic platform. Staged
  reasoning pipeline (intent → skill → read-only context → prompt → provider →
  citation validation → grounding validation → formatting); five skills; a
  provider-agnostic `ILLMProvider` port with a Claude implementation; in-memory
  sessions with analyst focus; grounded, cited answers; REST API + `BackendClient`
  gateway. The Copilot is never a source of truth (ADR-0002). No persistence, no
  database change, no repository change, no duplicated intelligence logic.
- **M12 Phase 2 — AI Security Copilot (User Experience)**: the MVVM Copilot page
  (chat, conversation history, message bubbles, typing indicator, auto-scroll,
  clear/copy/regenerate), context-aware suggested prompts, clickable citations
  that navigate via the existing router, "Ask Copilot" launch points from every
  investigation surface, and response metadata (skill, duration, provider,
  grounding; model + prompt version in developer mode). UI-only, over the Phase 1
  backend; no new intelligence logic and no direct service access.
- **M12 Phase 3 — AI Security Copilot Finalization** (M12 complete): streaming
  responses (additive `ILLMProvider.stream()` seam; `ClaudeProvider` SSE;
  grounding-preserving `stream_ask`; `POST /api/copilot/ask/stream`; lifecycle-safe
  `StreamWorker`; progressive UI with graceful non-streaming fallback), the final
  investigation-integration/grounding/session/provider reliability passes, UX
  polish, and a Qt lifecycle audit (the full UI suite exits cleanly). No backend
  redesign, no persistence, no database, no new engine/graph algorithm/AI
  abstraction.

**M12 is complete.** The AI Security Copilot is delivered end-to-end: a read-only,
grounded, cited, streamed interpretive layer over the deterministic platform,
never a source of truth (ADR-0002).

- **M13 — Authentication & Secure Application Entry** (delivered): professional
  single-user local authentication. First-launch registration → login → SOC
  Command Center; logout returns to login. stdlib scrypt password hashing (no new
  dependency), server-side bearer-token sessions in SQLite, API-level route
  protection on every analyst router, and a premium branded authentication UI
  covering all states. Not an enterprise identity system (no multi-user/RBAC/SSO/
  LDAP/cloud/multi-tenancy). Recorded in ADR-0003. **The authentication
  experience is considered complete** — nothing basic is deferred to the
  candidate release.

- **M14 — Gmail Intelligence Integration** (delivered): Gmail as a read-only
  input connector feeding the existing Email Analysis pipeline — not a new engine.
  Installed-app loopback OAuth 2.0 (system browser, ephemeral `127.0.0.1`
  callback), strictly the `gmail.readonly` scope, httpx (no Google SDK), tokens in
  a 0600 file outside the repo, all routes behind the M13 session guard (separate
  from the Gmail OAuth identity). Manual "Sync Now" (default 50, configurable),
  dedup by Gmail message id. Gmail-derived intelligence flows through the existing
  IOC/threat/incident/graph/analytics/SOC/Copilot with no Gmail-specific logic.
  Recorded in ADR-0004. **Completion pass (delivered):** an analyst message
  workspace — the account's messages listed with their existing verdict/risk,
  risk filters and search, message detail surfacing the existing analysis and a
  safe plain-text preview, and reuse-only navigation into the existing Email
  Investigation, Graph Explorer, and Copilot. Account-aware read-model (composite
  PK) for multi-account demonstrations; four-state sync taxonomy that explains the
  previously observed "1 error" as an unsupported message. Six gates green, 741
  tests, no new dependency.

## Next

- **M15 — Candidate Release** is the final milestone and will begin only after
  architectural review of M14. Not started.

**Persistence direction retired.** The previously suggested M12 persistence
direction (graph/session persistence behind `IGraphRepository`; Neo4j/Neptune/
JanusGraph/Cosmos DB) has been **explicitly declined**. The in-memory graph
architecture remains frozen and sufficient for the current scope; no persistence
layer is being introduced at this stage.

## Delivered backend concerns

- **Live graph population (M10):** detection services publish intelligence events
  onto the bus; the `GraphBuilder` populates the graph live. No change to the bus,
  builder, or Explorer was required — only `publish` calls at the detection sites,
  centralised in the `IntelligencePublisher` seam.

## Non-goals (current)

- Heavy graph algorithms (community detection, betweenness/eigenvector
  centrality, full path enumeration).
- Any persistence or stateful backend endpoints ahead of M10.

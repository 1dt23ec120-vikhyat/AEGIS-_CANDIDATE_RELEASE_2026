# Changelog

All notable changes to AEGIS+ are recorded here. Milestones are gated and
reviewed; each entry corresponds to an approved milestone. Dates are relative to
the milestone sequence rather than calendar dates.

## M14 — Gmail Intelligence Integration

### Added (completion pass — analyst workspace)
- **Gmail message workspace:** the Gmail Intelligence page now lists the account's
  actual messages with their **existing** AEGIS+ verdict/risk, plus risk filters
  (All / High Risk / Suspicious / Benign / Unanalyzed) and search. It is a security
  triage surface, not a mail client.
- **Message detail** surfaces the *existing* analysis for a selected message —
  verdict, risk %, confidence, triggered evidence, intelligence sources, IOCs, and
  incident/campaign association — with no recomputation. A **safe preview** renders
  the body as sanitized plain text; links are listed as untrusted and never opened
  automatically, and attachments are shown as metadata only.
- **Reuse-only navigation:** from a message the analyst opens the **existing** Email
  Investigation (`Open Investigation`, by `scan_id`), **Graph Explorer**
  (`Open in Graph Explorer`, focused on the email artifact), and **AI Copilot**
  (`Ask Copilot`, incident/artifact focus) — all through existing focus contracts.
- **Read-model:** minimal, non-secret message metadata persisted per account
  (`account_email`, `message_id`, `thread_id`, `sender`, `subject`, `received_at`,
  `snippet`, `status`, `scan_id`) via an additive migration; the composite primary
  key `(account_email, message_id)` makes deduplication and the workspace
  **account-aware** so multiple demonstration accounts never mix.
- **Four-state sync taxonomy** (`ANALYZED` / `UNSUPPORTED` / `TRANSIENT` /
  `FAILED`): an unsupported or malformed message no longer fails the whole sync; a
  transient Gmail error is not recorded and is retried next sync; the sync summary
  distinguishes successful analysis from messages that could not be analyzed.
- **API:** `GET /api/gmail/messages` (filter/search), `GET /api/gmail/messages/{id}`,
  and `GET /api/email/scans/{scan_id}` (opens the existing investigation) — all
  behind the AEGIS+ session guard, returning DTOs only.

### Fixed
- The previously observed **"1 error"** during synchronization is now explained
  rather than hidden: it is classified as an `UNSUPPORTED` (unparseable) message,
  recorded and shown to the analyst without a stack trace, and does not fail the
  synchronization.

### Added
- **Read-only Gmail connector** feeding the existing Email Analysis pipeline —
  Gmail is an input source, not a new analysis engine. Connect, sync, and
  disconnect from a polished **Gmail Intelligence** page (sidebar → Integrations).
- **Installed-app loopback OAuth 2.0** (ADR-0004): the system browser opens
  Google's consent page and AEGIS+ receives the result on a temporary
  `127.0.0.1` ephemeral-port callback — no code copy/paste, no embedded webview.
  The listener is lifecycle-safe (torn down on success, denial, timeout, error,
  and exit).
- **Gmail API:** `GET /api/gmail/status`, `POST /api/gmail/connect`,
  `POST /api/gmail/disconnect`, `POST /api/gmail/sync` — all behind the existing
  AEGIS+ session guard, and separate from the Gmail OAuth identity.
- **Manual synchronization** ("Sync Now"), default 50 most recent messages
  (configurable), with retrieved/analyzed/malicious/suspicious/benign/error
  statistics and last-sync time.
- **Deduplication** by Gmail message id (`gmail_processed_messages`): repeated
  syncs never re-analyze a message.
- Gmail-derived intelligence flows through the existing IOC extraction, threat
  intelligence, incident/campaign correlation, event bus, knowledge graph,
  analytics, SOC, and Copilot — with no Gmail-specific engine, graph, or skill.

### Security
- Strictly the `gmail.readonly` scope, enforced by a config validator at load.
- OAuth client secret from `AEGIS_GMAIL_CLIENT_SECRET`; tokens stored in a 0600
  file under `data/gmail/`, outside the repository and gitignored; never logged,
  returned, shown in the UI, or placed in Copilot context.
- All Gmail routes require an AEGIS+ session; Gmail OAuth and AEGIS+ login are
  kept separate.

### Database
- One additive Alembic migration adds `gmail_processed_messages`; no existing
  table changed; Alembic no-drift holds (10 migrations).

### Unchanged
- No new dependency (Gmail uses the existing `httpx`; no Google SDK). No completed
  system was redesigned. All prior tests pass (678 prior + 42 new = 720).

## M13 — Authentication & Secure Application Entry

### Added
- **Single-user local authentication.** First-launch registration (full name,
  username, email, password) with professional validation and a polished success
  state; subsequent launches open to login. Exactly one local account per
  installation (no multi-user, RBAC, SSO, LDAP, cloud identity, or multi-tenancy).
- **Secure password hashing** with stdlib `hashlib.scrypt` (memory-hard, no new
  dependency): per-account random salt, self-describing hash string,
  constant-time verification. See ADR-0003.
- **Sessions & logout.** Server-side opaque bearer-token sessions with expiry,
  stored in SQLite; a Sign-out action in the shell top bar invalidates the
  session and returns to login; expired sessions return to login with a notice.
- **Authentication API:** `GET /api/auth/status`, `POST /api/auth/register`
  (201/409/422), `POST /api/auth/login` (200/401), `GET /api/auth/me`,
  `POST /api/auth/logout` (204). Password hashes are never returned; errors are
  generic to prevent account enumeration.
- **API-level route protection.** Every analyst router (analysis, email, file,
  threats, incidents, soc, graph, analytics, copilot) requires a valid session
  via a `require_session` dependency; enforcement is at the API boundary, not
  merely UI hiding.
- **Premium authentication UI:** a branded `AuthWindow` (hero panel + login /
  register / loading / success cards) consistent with the SOC Command Center,
  with password visibility toggle, inline validation, password-strength feedback,
  logical Tab order, Enter-to-submit, and all authentication states.
- **Startup flow:** application launch → backend → authentication state check →
  auth window or (after login) the application shell. The shell is never built
  until authenticated.

### Changed
- The desktop client attaches the session bearer token to all backend calls and
  routes back to login on a backend 401 (session expired).
- The shell top bar gains a logout action and an account avatar.

### Database
- One additive Alembic migration adds `user_accounts` and `auth_sessions`; no
  existing table changed; Alembic no-drift holds (9 migrations).

### Fixed
- Clean Qt shutdown on logout: the backend health poller no longer emits after
  the shell is torn down (active guard + task drain).

### Unchanged
- No completed system was redesigned; no new dependency was added (scrypt is
  stdlib). All prior functionality works after authentication; all prior tests
  pass. Totals: 637 prior + 41 new = 678 tests (479 non-UI + 199 UI).

## M12 Phase 3 — AI Security Copilot Finalization (M12 complete)

### Added
- **Streaming responses.** Optional `stream()`/`supports_streaming()` on
  `ILLMProvider` (additive, safe defaults) + `LLMStreamChunk`;
  `BaseLLMProvider.stream()` over server-sent events; `ClaudeProvider` SSE
  streaming and parser.
- **Grounding-preserving streaming.** Orchestrator `stream_ask()` streams raw
  tokens for responsiveness but runs citation + grounding validation on the
  complete text and emits the validated response on a terminal `final` event
  (`CopilotStreamEvent`). ADR-0002 holds under streaming.
- **Streaming transport.** `POST /api/copilot/ask/stream` (SSE); the existing
  `/ask` is unchanged and remains the fallback. `BackendClient.copilot_stream()`
  yields typed events and falls back gracefully on transport error.
- **Streaming UI.** Lifecycle-safe `StreamWorker`; view-model `token_received`
  signal, streaming dispatch with automatic non-streaming fallback, and
  `dispose()`; page progressive token rendering, generating state, and worker
  disposal on close and application shutdown.

### Reliability & safety
- Verified grounding at the boundaries (nonexistent artifact, invalid/missing
  citation, insufficient context) and provider failure modes (unavailable,
  timeout, malformed, network, interrupted stream, empty) — all analyst-friendly,
  never a stack trace.
- Qt lifecycle audit: the streaming worker owns and joins its thread and is torn
  down on clear/regenerate/new-request/close/shutdown. The full UI test suite
  exits cleanly with no native crash or leaked worker.

### Unchanged
- No backend redesign; the `ILLMProvider` contract is extended only additively.
  No new engine, graph algorithm, persistence, database, or AI abstraction. No
  schema change (8 migrations, no drift); no configuration change. All 610 prior
  tests pass unchanged; 27 new tests added (637 total).

## M12 Phase 2 — AI Security Copilot (User Experience)

### Added
- **AI Copilot page** (`ui/pages/copilot.py`): a chat workspace with conversation
  history, user/assistant message bubbles, a typing indicator, auto-scroll, clear
  conversation, copy response, and regenerate response.
- **`CopilotViewModel`** (`ui/viewmodels/copilot.py`): MVVM view-model that owns
  the active-session conversation and runs `copilot_ask`/`copilot_update_focus`/
  `copilot_close_session` off the UI thread; exposes turn/busy/error/cleared/focus
  signals; maps provider failures to analyst-friendly messages.
- **Chat components** (`ui/components/copilot/chat.py`): `MessageBubble`,
  `CitationChip`, `CitationsRow`, `MetadataRow`, `TypingIndicator`,
  `SuggestedPrompts`, `ChatComposer` (Enter=send, Shift+Enter=newline).
- **Clickable citations:** `citation_target` maps a citation to the Graph Explorer
  via the existing `{focus, origin}` routing contract; chips navigate to the
  referenced node.
- **Context-aware suggested questions** that submit predefined prompts.
- **"Ask Copilot" launch points** from URL, email, and file investigations,
  incident triage, the Graph Explorer (selected node), and the SOC dashboard —
  each passing `{focus, kind, origin}` so the backend collects the context.
- **Response metadata:** active skill, response duration, provider, and grounding
  score, with model id and prompt version in developer mode.
- **Shell integration:** `Route.COPILOT` and an "AI Copilot" sidebar entry; a new
  `copilot` icon; a Copilot QSS section in the shared stylesheet.

### Unchanged
- No backend change (Phase 1 pipeline, services, REST API, and DTOs untouched); no
  API change; no configuration change; no database change (schema and all 8
  migrations unchanged; no drift). All 572 prior tests pass unchanged; 38 new UI
  tests added (610 total). All 7 Import Linter contracts kept.

## M12 Phase 1 — AI Security Copilot (Reasoning Engine)

### Added
- **AI Security Copilot** (`services/copilot/`): a read-only, natural-language
  interpretive layer over the deterministic platform. It explains and reasons
  over existing intelligence and is never a source of truth (ADR-0002).
- **Reasoning pipeline:** `CopilotOrchestrator` sequencing deterministic intent
  detection → skill selection → read-only context collection → prompt building →
  provider inference → citation validation → grounding validation → response
  formatting; each stage independently testable.
- **Five skills** (Threat Investigation, IOC Intelligence, Graph Reasoning,
  Incident Analysis, Executive Summary) via a `SkillRegistry` and the
  `ICopilotSkill` port — extensible by registration only.
- **Read-only context collection:** `ContextCollector` reads only the existing
  M11 analytics/graph/attack/recommendation services and renders their DTOs to
  severity-ranked, token-budget-bounded context; no intelligence logic
  reimplemented.
- **Grounding & citations:** context-only system prompt with mandatory
  `[cite:KIND:ID]` citations; `CitationValidator` resolves markers against the
  provided context; `GroundingValidator` scores citation coverage and (in strict
  mode) refuses ungrounded answers.
- **Provider-agnostic inference:** Core `ILLMProvider` port with a `ClaudeProvider`
  (Anthropic Messages API over `httpx`) on a shared `BaseLLMProvider`, selected by
  a config-driven factory; a streaming seam is reserved for Phase 2; any provider
  failure degrades gracefully to an "unavailable" response.
- **In-memory sessions:** `SessionManager` (LRU-bounded, per-session turn cap)
  with analyst `FocusState`; no persistence, no database.
- **REST API:** `POST /api/copilot/ask`, `GET`/`DELETE /api/copilot/session/{id}`,
  `POST /api/copilot/session/{id}/focus`; `BackendClient` gateway methods.
- **Observability:** `ai-copilot` health component (optional — never degrades
  platform status); uniform per-operation metrics via `MeteredService`.
- **Configuration:** new `copilot` section (`config/copilot.yaml`, env overrides
  `AEGIS_COPILOT_ENABLED`/`PROVIDER`/`MODEL`); API key read from the environment
  variable named by `copilot.api_key_env` (no secret stored in config).
- Documentation: `docs/architecture/AI_Security_Copilot.md` and
  `docs/architecture/adr/ADR-0002-copilot-not-source-of-truth.md`.

### Unchanged
- No database change (schema and all 8 migrations unchanged; no drift). No
  breaking changes to existing endpoints or UI. No new runtime dependency. All
  527 prior tests pass unchanged; 45 new tests added (572 total). All 7 Import
  Linter contracts kept.

## M10 — Live Intelligence Pipeline

### Added
- **Single publishing seam** `IntelligencePublisher` (`services/pipeline/`):
  centralises all intelligence-event construction so no publisher logic is
  duplicated across detection services. Best-effort publishing — failures are
  counted/logged and never break an analysis.
- **Detection services publish events:** URL, email, and file analysis publish
  `artifact_analyzed` (+ `ioc_extracted`, per-IOC/embedded-URL
  `relationship_discovered`, and `threat_recorded` when malicious); email and file
  publish `incident_created`/`campaign_created` on correlation; the investigation
  services publish `investigation_completed` on save.
- **`investigation_completed` event constructor** (the `INVESTIGATION_COMPLETED`
  type already existed).
- **Live graph population:** the already-subscribed `GraphBuilder` now builds the
  knowledge graph from these events; the Intelligence Graph Explorer reflects
  newly analysed intelligence with no redesign.
- **Observability:** enriched `event-bus` health (published/dispatched/failures)
  and new `graph-builder` and `intelligence-publisher` health components;
  per-type publisher metrics.
- Documentation: Live Intelligence Pipeline architecture; Event Bus, Knowledge
  Graph, Graph Explorer, Backend Boundary, and API docs updated to remove the
  deferred-publishing caveat.

### Notes
- No persistence, no database technology, and no repository-interface change.
  Publisher injection is optional (default `None`), preserving full backward
  compatibility. Zero regressions; no schema change (migration head unchanged).

## M11 — Advanced Threat Analytics & Intelligence Engine

### Added
- **Graph Analytics (Phase A):** `GraphAnalyticsService` — degree, centrality
  ranking, connected components, density, blast radius, reachability, shortest
  attack paths, multi-hop neighbourhood, shared-infrastructure discovery, threat
  propagation (composes `GraphQueryService`).
- **Threat Intelligence (Phase B):** IOC intelligence (frequency, prevalence,
  reuse, confidence, aging), campaign intelligence (size, evolution, Jaccard
  similarity), explainable threat scoring (severity, exposure, confidence,
  priority, analyst urgency).
- **Attack Analysis (Phase C):** attack-chain reconstruction, kill-chain mapping,
  compromise-path discovery, root-cause analysis, infrastructure clusters,
  attack-timeline reconstruction, threat propagation.
- **Recommendations (Phase D):** deterministic, explained recommendations (next
  investigation, priority IOC, risk campaign, suspicious relationship, containment
  order, investigation sequence).
- **SOC & Explorer (Phase E):** `AnalyticsOverviewService`, `GraphOverlayService`,
  `GET /api/analytics/overview` and `/api/analytics/overlay`, `BackendClient`
  gateway, an additive SOC dashboard "Advanced Threat Analytics" section, and a
  Graph Explorer "Analytics Overlay" toggle.
- Shared `MeteredService` + `tracked` observability; reusable
  `GraphQueryService.all_nodes()`; `graph-analytics` and aggregate
  `intelligence-engine` health components.
- Documentation: `docs/architecture/Advanced_Threat_Analytics.md`.

### Notes
- All analytics deterministic and explainable; composes existing services only —
  no redesign, no persistence, no database, no repository change, no duplicated
  algorithms. Zero regressions; no schema change.

## M9 Phase 3-C — Graph Explorer Hardening, Observability & Release

### Added
- **Lightweight graph analytics:** real (BFS-based) `centrality`,
  `connected_components`, `graph_density`, `blast_radius`, and shortest-path
  `attack_paths` on `GraphQueryService`; `communities` explicitly out of scope.
- Analytics summary extended with `relationship_type_counts`, `component_count`,
  and `density` (additive; surfaced through API, client, and the Analytics panel
  with entity/relationship distributions).
- **Observability:** view-model `metrics_ready` signal carrying layout, render,
  backend-query, expansion, search, and timeline-filter durations plus node/edge/
  visible/hidden/expansion/depth counts; backend `GraphExplorerService.metrics()`
  surfaced via a new `graph-explorer` health component.
- **Session preparation:** in-memory `ExplorerSessionState`/`ViewportState` with
  page-level `session_state()`/`restore_session()` (no persistence).
- **Polish:** keyboard navigation on the canvas (+/− zoom, F/Home fit, arrow-key
  pan) and viewport capture/restore.
- Documentation: Graph Explorer architecture, backend boundary, knowledge graph,
  event-bus interaction, ADR-0001, Graph API reference, developer guide, user
  guide, changelog, roadmap.

### Notes
- No persistence introduced; repository interfaces unchanged; detection-service
  event publishing remains deferred. Zero regressions.

## M9 Phase 3-B — Intelligence Graph Explorer (MVVM Presentation Layer)
- Interactive graph canvas (pan/zoom/drag/fit/focus/hover-highlight/visibility
  filtering), toolbar, and analyst panels (search+history, filters, timeline,
  node/relationship details, analytics, legend).
- `GraphExplorerViewModel` (MVVM) and `GraphExplorerPage`; payload-aware
  navigation; File Investigation ↔ Explorer integration.
- Injectable runner factory for deterministic UI tests.

## M9 Phase 3-A — Graph Explorer Application Layer
- Graph presentation view DTOs, `GraphExplorerService`, `/api/graph/*`, and the
  `BackendClient` graph gateway.

## M9 Phase 3.0 — Baseline Architecture Remediation
- Restored 7/7 Import Linter contracts (Services→AI and UI→Services severed).

## M9 Phase 2 — Knowledge Graph Domain
- Graph domain, `IGraphRepository` port, `InMemoryGraphRepository`,
  `GraphBuilder`, `GraphQueryService`.

## M9 Phase 1 — Internal Intelligence Event Bus
- `IEventBus`, `IntelligenceEvent`, `InProcessEventBus`, `EventHistory`.

## M4–M7 — Detection & SOC
- URL, Email, and File intelligence engines; incident/campaign correlation; the
  SOC Command Center. (See `PROJECT_PROGRESS.md` for detail.)

# AI Security Copilot — Architecture (M12)

The AI Security Copilot is a read-only, natural-language interpretive layer over
the AEGIS+ deterministic intelligence platform. It answers analyst questions by
gathering the platform's existing intelligence, grounding a language model on
that intelligence, and returning a cited, verifiable answer. It is never a source
of truth (see [ADR-0002](adr/ADR-0002-copilot-not-source-of-truth.md)).

## Position in the architecture

```
UI (BackendClient)  ──HTTP──►  application/api/copilot.py
                                        │
                                        ▼
                              services/copilot (pipeline)
                                        │  read-only calls
                                        ▼
             existing M11 analytics / graph / attack / recommendation services
                                        │
                                        ▼
                          core ports + domain (authoritative)

services/copilot ──uses──► core/interfaces/llm_provider (ILLMProvider)
                                        ▲ implemented by
                              ai/copilot/providers (Claude, …)
```

Dependency directions are unchanged and all seven Import Linter contracts hold:
`core` imports nothing internal; `services/copilot` imports `core` (and other
`services`, intra-layer); `ai/copilot` implements a `core` port; `ui` reaches the
Copilot only over HTTP.

## The reasoning pipeline

The `CopilotOrchestrator` sequences discrete, independently testable stages:

| # | Stage | Component | Responsibility |
|---|-------|-----------|----------------|
| 1 | Intent detection | `IntentDetector` | Deterministic keyword + focus rules → `DetectedIntent`. Never uses the LLM. |
| 2 | Skill selection | `SkillRegistry` | Maps intent → a registered `ICopilotSkill`. |
| 3 | Context collection | `ContextCollector` | Read-only calls to existing services; renders DTOs to ranked `ContextItem`s. |
| 4 | Prompt building | `PromptBuilder` | Scaffold + skill fragment + context + history; records `PromptMetadata`. |
| 5 | Inference | `ILLMProvider` | Provider-agnostic completion; graceful failure. |
| 6 | Citation validation | `CitationValidator` | Resolves `[cite:KIND:ID]` markers against the provided context. |
| 7 | Grounding validation | `GroundingValidator` | Scores citation coverage; strict mode refuses ungrounded answers. |
| 8 | Formatting | `ResponseFormatter` | Assembles the final `CopilotResponse` with related references. |

The orchestrator holds only the sequence and the session write-back; it contains
no intelligence logic.

## Skills

Five focused skills ship in Phase 1, each declaring the intent it serves, the
context scope the collector runs, and a prompt fragment:

- **Threat Investigation** — explains an artifact's verdict, score, and IOCs
  (scope: artifact).
- **IOC Intelligence** — explains indicator frequency, prevalence, reuse, and
  aging (scope: artifact).
- **Graph Reasoning** — explains neighbourhood, blast radius, and centrality
  (scope: artifact).
- **Incident Analysis** — explains root cause, attack chain, and affected
  artifacts (scope: incident).
- **Executive Summary** — summarises the current posture from top threats,
  campaigns, IOCs, and recommendations (scope: global).

New skills plug in by registration only; the orchestrator, pipeline, and
collector are untouched.

## Context collection and ranking

The `ContextCollector` is the read-only bridge to platform intelligence. Per
scope it calls the relevant services — `ThreatScoringService`,
`IOCIntelligenceService`, `CampaignIntelligenceService`, `AttackAnalysisService`,
`GraphAnalyticsService`, `GraphQueryService`, `RecommendationService`,
`AnalyticsOverviewService` — and renders each returned DTO to a deterministic
text block via the serializers. Items are ranked by the platform's own severity
signal and bounded by a configurable token budget, so the most important
intelligence survives truncation. The knowledge graph is used to *discover*
related intelligence (for example, walking to an artifact's IOC neighbours)
rather than matching on keywords.

## Grounding and citations

The system prompt establishes the grounding contract: answer only from context,
cite every claim, and admit insufficiency rather than guess. Each context block
is labelled with the exact `cite` key the model must reuse. After generation the
`CitationValidator` resolves every marker against the supplied context —
producing `Citation` objects for resolved markers and violations for unknown
ones — and the `GroundingValidator` computes a grounding score from citation
coverage. In strict mode an answer with no resolved citations is replaced by an
explicit "insufficient intelligence" message.

## Provider abstraction

`ILLMProvider` is the Core-owned, provider-agnostic inference port. Phase 1 ships
`ClaudeProvider` (Anthropic Messages API over `httpx`) built on a shared
`BaseLLMProvider`. The provider factory selects the implementation from
configuration; the orchestrator only ever sees the interface. A missing
credential or any transport failure yields an unsuccessful `LLMResult` (never an
exception), and the orchestrator degrades to an "unavailable" response. A
streaming seam (`supports_streaming`) is reserved for Phase 2 without committing
to an implementation.

## Sessions

`SessionManager` holds conversations entirely in memory — no persistence, no
database, consistent with the platform's in-memory-first posture. It is bounded
by LRU eviction and a per-session turn cap, and also holds the analyst focus
state (current artifact/incident/campaign), which the UI updates and the Copilot
reads for intent resolution and ranking.

## Observability

The orchestrator and collector extend `MeteredService`, so per-operation timings
and counts are uniform with the rest of the platform. An `ai-copilot` health
component reports the subsystem as active (it degrades gracefully), the active
provider, its readiness, queries served, and active sessions. Because the Copilot
is optional, this component never degrades platform status.

## API surface

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/copilot/ask` | Answer a question (grounded, cited). |
| POST | `/api/copilot/session/{id}/focus` | Record the analyst's current focus (in memory). |
| GET | `/api/copilot/session/{id}` | Inspect an in-memory conversation. |
| DELETE | `/api/copilot/session/{id}` | Close an in-memory conversation. |

The UI reaches these only through `BackendClient.copilot_ask`,
`copilot_update_focus`, and `copilot_close_session`.

## Configuration

The `copilot` settings section governs the provider, model, endpoint, the
environment variable to read the API key from (no secret is stored in config),
generation limits, the context token budget, session capacity, and the grounding
mode. Env overrides: `AEGIS_COPILOT_ENABLED`, `AEGIS_COPILOT_PROVIDER`,
`AEGIS_COPILOT_MODEL`. The API key is supplied via the environment variable named
by `copilot.api_key_env` (default `ANTHROPIC_API_KEY`).

## What is frozen

Every detection engine, fusion, correlation, threat intelligence, campaign
intelligence, the knowledge graph and its repository, the event bus, all M11
analytics services, the SOC overview, the database schema and all eight
migrations, and all existing API endpoints and UI pages remain unchanged. The
Copilot is entirely additive and read-only.

## Presentation layer (M12 Phase 2)

Phase 2 adds the analyst-facing Copilot interface on top of the Phase 1 backend.
It is pure MVVM presentation and reaches the backend only through
`BackendClient` — it holds no intelligence logic and accesses no service
directly.

### Components

| Layer | Component | Responsibility |
|-------|-----------|----------------|
| View-model | `CopilotViewModel` (`ui/viewmodels/copilot.py`) | Owns the active-session conversation (`ChatTurn`s); runs `copilot_ask`/`update_focus`/`close_session` off the UI thread via an injected `AsyncRunner`; exposes turn/busy/error/cleared/focus signals; maps provider failures to analyst-friendly messages. |
| Page | `CopilotPage` (`ui/pages/copilot.py`) | Auto-scrolling transcript, composer, suggested prompts, clear/regenerate/copy, developer-mode metadata, citation click-through, and the `on_navigated` launch hook. |
| Components | `ui/components/copilot/chat.py` | `MessageBubble`, `CitationChip`, `CitationsRow`, `MetadataRow`, `TypingIndicator`, `SuggestedPrompts`, `ChatComposer` (Enter=send, Shift+Enter=newline). |
| Navigation | `ui/components/copilot/navigation.py` | Maps a `Citation` to a `(Route, payload)` target, reusing the Graph Explorer's `{focus, origin}` contract. |

### Conversation flow

The composer (or a suggested prompt) submits a question to the view-model, which
shows the user bubble and a typing indicator, calls the backend off-thread, then
fills in the assistant bubble with the grounded answer, a row of clickable
citation chips, and a metadata line (skill, duration, provider, grounding score;
model and prompt version in developer mode). Regenerate re-asks the last question
in place; clear closes the in-memory session. The single `_dispatch`/`_ask` seam
is the only place a streaming provider would change; because the Phase 1 provider
does not advertise streaming, the page uses the standard path and falls back
gracefully.

### Launch points

An "Ask Copilot" action is available from URL, email, and file investigations,
incident triage, the Graph Explorer (selected node), and the SOC dashboard
(global posture). Each navigates to the Copilot route with a payload of
`{focus, kind, origin}`; the page sets the focus context and the *backend*
performs all context collection — the UI never collects context itself. Citation
chips navigate to the referenced node in the Graph Explorer via the existing
router.

### Error handling & accessibility

Provider-unavailable, timeout, network, and insufficient-context conditions are
surfaced as calm, analyst-friendly messages; no stack trace is ever shown. The
composer supports Enter-to-send and Shift+Enter for a newline, keyboard focus
indicators, scalable fonts from the design tokens, and high-DPI rendering, all
consistent with the rest of the platform. A new `copilot` icon and the "AI
Copilot" sidebar entry integrate the surface into the shell.

## Streaming (M12 Phase 3)

Phase 3 implements the reserved streaming seam end-to-end while keeping the
`ILLMProvider` contract and the grounding guarantees intact.

### Provider

`ILLMProvider` gains two *optional* members with safe defaults —
`supports_streaming()` (default `False`) and `stream()` (default yields a single
terminal "unsupported" chunk). This is additive: existing providers and callers
are unaffected. `BaseLLMProvider.stream()` performs the SSE round-trip over
`httpx`, translating every failure (missing credential, non-200, transport error,
malformed line) into a terminal `LLMStreamChunk` with `success=False` rather than
raising. `ClaudeProvider` advertises streaming and parses the Anthropic
server-sent-event sequence (`content_block_delta` text deltas; `message_start`/
`message_delta` token usage).

### Orchestrator — grounding is preserved

The pipeline is factored into a shared `_prepare` (stages 1–4) and `_finalize`
(stages 6–8). `stream_ask()` runs `_prepare`, streams raw token events from the
provider for UI responsiveness, then assembles the complete text and runs it
through `_finalize` — the **same citation and grounding validation as the
non-streaming path**. The terminal `final` event carries the validated
`CopilotResponse`; the streamed tokens are never the authoritative answer. Thus
ADR-0002 holds under streaming: the Copilot cannot fabricate intelligence, and an
ungrounded stream is finalized as an honest "insufficient intelligence" answer.
Any provider or stream failure yields an `error` event with a graceful fallback
response.

### Transport

A new `POST /api/copilot/ask/stream` endpoint returns `text/event-stream`,
serializing each `CopilotStreamEvent` as an SSE `data:` frame (`token`, `final`,
or `error`). The non-streaming `/ask` endpoint is unchanged and remains the
fallback. `BackendClient.copilot_stream()` consumes the SSE stream and yields
typed events, degrading to a single graceful `error` event on any transport
failure.

### UI — progressive rendering and Qt lifecycle safety

The view-model consumes the stream through a dedicated, lifecycle-safe
`StreamWorker`:

- The worker runs on a `QThread` it owns and is explicitly cancelled, quit, and
  joined by `stop()`, so no worker survives the page or the `QApplication`.
- A cooperative cancellation flag ends an in-flight stream promptly on clear,
  regenerate, a new request, or page destruction; signals are dropped after
  cancellation so a late chunk cannot touch a torn-down view.
- The view-model tears the worker down on `clear()`, on each new dispatch, and on
  `dispose()`; the page calls `dispose()` from `closeEvent` and connects it to
  `QApplication.aboutToQuit`.

The page shows a typing indicator until the first token, then fills the assistant
bubble progressively, keeps auto-scroll safe (the Phase 2 page-parented timer),
and remains scrollable during generation. When the provider does not advertise
streaming, or streaming fails, the view-model falls back to the non-streaming
path automatically. The full UI test suite exits cleanly with no native Qt crash
or leaked worker.

# AEGIS+ Gmail Intelligence Integration (M14)

## Purpose

M14 adds **Gmail as a read-only intelligence source** that feeds the existing
AEGIS+ Email Analysis pipeline. It is not a new email-security engine and adds no
Gmail-specific analysis. The design decisions are recorded in ADR-0004.

## Flow

```
Google Gmail
  → Google OAuth 2.0 (installed-app loopback, system browser)
  → Gmail Gateway (httpx REST, read-only)
  → Gmail Ingestion Service   (dedup by Gmail message id)
  → EXISTING EmailAnalysisService.analyze(raw_email)
  → existing IOC extraction, threat intelligence, incident/campaign correlation
  → IntelligencePublisher → event bus
  → Knowledge Graph, Advanced Analytics
  → SOC Command Center
  → AI Security Copilot
```

Gmail never bypasses the existing intelligence architecture; it is an input
connector only.

## Layering (all 7 Import Linter contracts intact)

| Layer | Gmail additions |
|-------|-----------------|
| **core** | `domain/gmail.py` (`GmailCredentials`, `GmailAccount`, `GmailMessageRef`, `GmailRawMessage`); ports `IGmailAuthFlow`, `IGmailTokenStore`, `IGmailGateway`, `IGmailSyncStateRepository`. Framework-free. |
| **config** | `schemas/gmail.py` (`GmailSettings`, read-only-scope validator) + `gmail.yaml`. |
| **infrastructure** | `integrations/gmail/` — `LoopbackGmailAuthFlow`, `HttpxGmailGateway`, `FileGmailTokenStore` (all httpx/stdlib, no Google SDK); `repositories/gmail_sync_state_repository.py`; ORM row `GmailProcessedMessageRow`. |
| **services** | `gmail/service.py` (`GmailIngestionService`) — connection management + manual sync; reuses `EmailAnalysisService.analyze` verbatim. |
| **application** | `api/gmail.py` (`/api/gmail/*` behind `require_session`); container `_build_gmail`; one additive migration. |
| **ui** | `viewmodels/gmail.py` (`GmailViewModel`); `pages/gmail.py` (`GmailPage`); `BackendClient` Gmail methods; a "Gmail Intelligence" sidebar entry in an Integrations section. |

The Email engine, knowledge graph, and Copilot never import Gmail or Google
types; all Google specifics stay behind the ports in infrastructure.

## OAuth architecture (loopback)

1. AEGIS+ binds a temporary listener to `127.0.0.1` on an **ephemeral** port.
2. It opens the **system browser** to Google's consent page with a `state` nonce
   and the loopback `redirect_uri`.
3. Google redirects back to the loopback with an authorization code; the listener
   validates the `state` nonce and captures the code.
4. AEGIS+ exchanges the code for tokens over `httpx`.

No copy/paste, no embedded webview. The listener is lifecycle-safe: bound to
loopback only, alive for a single authorization, and torn down on success,
denial, timeout, error, and process exit. The connect flow runs on the backend
threadpool (a sync FastAPI handler) so the UI event loop is never blocked, and
the UI runs it off-thread via the view-model so the app stays responsive.

## Scope

Strictly `https://www.googleapis.com/auth/gmail.readonly`. `GmailSettings`
rejects any other scope at load time. AEGIS+ never sends, deletes, moves, labels,
marks-read, or otherwise modifies mail.

## Message processing & deduplication

Messages are fetched as raw RFC-822 (`format=raw`, base64url-decoded) and passed
straight to `EmailAnalysisService.analyze(raw_email)` — the same seam the manual
email scanner uses — so no parser or detection logic is duplicated.

Deduplication uses the Gmail **message id** as the external identity, recorded in
the additive `gmail_processed_messages` table. Repeated syncs skip already-processed
messages (no re-fetch, no re-analysis). The table stores no message content and no
OAuth secret — only the id, the resulting scan id, and a timestamp.

## Synchronization

Manual **Sync Now** is the primary workflow for M14. The default bound is the 50
most recent messages, configurable via `gmail.max_list_results`
(`config/gmail.yaml`) and the sync request. The sync reports retrieved / analyzed
/ duplicates / malicious / suspicious / benign / errors and the last-sync time.

**Automatic monitoring** is intentionally OFF for M14 and shown as such. The
architecture leaves a clean seam for a future conservative poller: a scheduler
could call `GmailIngestionService.sync()` on an interval without any change to the
connector, because sync is idempotent (dedup) and self-contained. No background
daemon, queue, or scheduler is introduced in M14.

## Disconnect

Disconnect clears the local OAuth tokens and the dedup state and returns the UI to
the disconnected state. It does **not** erase previously generated AEGIS+
intelligence (threats, incidents, graph, scans) — those persist per existing
retention.

## Security & privacy

See `docs/architecture/Gmail-Security.md` and ADR-0004. In summary: read-only
scope only; client secret from the environment; tokens in a 0600 file outside the
repo; tokens never logged, returned, shown, or placed in Copilot context; all
routes behind the AEGIS+ session guard; Gmail OAuth kept separate from AEGIS+
login.

## Testing

All Google/network behaviour is mocked. Coverage: OAuth (URL generation, callback
success/denial/timeout/state-mismatch, token exchange, refresh, missing
credentials), gateway (profile/list/fetch-raw, raw decode, 401/500/network),
token store (roundtrip, 0600, corruption, clear), ingestion service (dedup,
refresh-on-expiry, stats, partial failure, disconnect), API endpoints (auth
boundary, no-secret responses, graceful errors), and the UI page states. One
end-to-end test drives a fake Gmail gateway → `GmailIngestionService` → the
**real** `EmailAnalysisService` → real graph/correlation, asserting a Gmail
phishing message produces real intelligence and graph nodes. No test needs a
Google account, live Gmail, live OAuth, or network.

---

## Analyst Workspace & Read-Model (M14 completion pass)

### Principle

The workspace is a **read-model + presentation + navigation** layer over the
existing intelligence. Gmail messages already flow through
`EmailAnalysisService.analyze()`, so they already participate in IOC extraction,
threat intelligence, incident/campaign correlation, the event bus, the knowledge
graph, SOC aggregation, and Copilot context. The workspace **exposes and links to**
that intelligence; it never recomputes it and adds no Gmail-specific engine.

### Data flow

```
Gmail message id ──(gmail_processed_messages)──▶ scan_id
                                                   │
                                                   ▼
                             EmailAnalysisService.get_scan(scan_id)  ── verdict/risk/evidence/sources
                                                   │
        IncidentCorrelationService.list_incidents()│  ── incident/campaign association (read-only)
                                                   │
             on-demand gateway.fetch_raw + EmailMessage.parse  ── safe preview + graph artifact id
```

### Read-model

`gmail_processed_messages` (composite PK `(account_email, message_id)`) stores only
non-secret metadata — `thread_id`, `sender`, `subject`, `received_at`, `snippet`,
`status`, and the resulting `scan_id`. No body, no full headers, no attachments, no
OAuth material. The `account_email` scope makes deduplication and the message list
**account-aware**, so multiple demonstration accounts stay isolated and a
disconnect/reconnect starts clean. Migration: `32799204f010` (additive).

### Four-state ingestion taxonomy

| State | Meaning | Recorded? | Retried? |
|-------|---------|-----------|----------|
| `ANALYZED` | Flowed through the pipeline; produced a scan | Yes | — |
| `UNSUPPORTED` | Raw could not be parsed (malformed/unsupported RFC-822) | Yes | No |
| `TRANSIENT` | Temporary Gmail/API failure while fetching | **No** | Yes (next sync) |
| `FAILED` | Unexpected error during analysis | Yes | No |

A single unsupported/failed message never fails the whole synchronization. This is
the resolution of the previously observed "1 error": it is an `UNSUPPORTED` message,
recorded and shown to the analyst without a stack trace.

### Safe preview

The message detail fetches the raw message on demand and renders it as **sanitized
plain text**. Links are listed as untrusted and never opened automatically; remote
content and scripts are never loaded; attachments are shown as metadata only. The
purpose is to help the analyst decide whether a message is safe *before* interacting
with it in Gmail.

### Reuse-only navigation

- **Open Investigation** → the existing Email Investigation, keyed by `scan_id`
  (`EmailScannerPage.on_navigated({"scan_id"})`).
- **Open in Graph Explorer** → `{focus: <email artifact id>, origin: GMAIL}` using
  the Explorer's existing focus contract; the artifact id matches
  `EmailMessage.identity`, the node id the event bus already publishes.
- **Ask Copilot** → `{focus, kind: incident|artifact, origin: GMAIL}` using the
  Copilot's existing focus contract; the Copilot reasons over the deterministic
  AEGIS+ findings and remains read-only/grounded (ADR-0002).

### API

All session-guarded (M13), DTOs only, no token material:

- `GET /api/gmail/messages?risk_filter=&search=` — the analyst message list.
- `GET /api/gmail/messages/{id}` — full detail (existing analysis + safe preview).
- `GET /api/email/scans/{id}` — opens the existing investigation for a scan.

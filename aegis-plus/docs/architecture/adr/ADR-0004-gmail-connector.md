# ADR-0004 — Gmail Read-Only Connector: httpx over the Google SDK, and the Loopback OAuth Flow

- **Status:** Accepted (M14)
- **Context date:** M14
- **Deciders:** Architecture review (gated milestone approvals)

## Context

M14 adds Gmail as a real-world intelligence **source** feeding the existing Email
Analysis pipeline. It is explicitly **not** a new email-security engine: Gmail is
an input connector. Two decisions needed recording — how AEGIS+ talks to Google
(HTTP client vs. Google SDK), and how it obtains authorization (which OAuth flow)
— along with where the connector's code and secrets live so the frozen
architecture and its seven Import Linter contracts stay intact.

Constraints carried in from the milestone brief and the project constitution:

- The connector must reuse `EmailAnalysisService.analyze(raw_email)` and add no
  Gmail-specific analyzer, IOC engine, scoring, graph, or Copilot skill.
- Only the read-only Gmail scope (`gmail.readonly`) may be requested.
- OAuth tokens and the client secret must never be committed, logged, or exposed
  through logs, exceptions, the UI, API responses, or Copilot context.
- No unjustified new dependency; keep the frozen stack.
- Gmail OAuth (authorizing AEGIS+ to read a mailbox) is a separate concern from
  the AEGIS+ application login (M13).

## Decision

### 1. HTTP client: `httpx`, not the Google SDK

The connector talks to Google's OAuth token endpoint and the Gmail REST API
directly over `httpx`, which is already in the frozen stack and used throughout
AEGIS+. We do **not** add `google-api-python-client` or `google-auth`.

The surface the connector needs is small and stable: the OAuth authorization URL,
the token exchange/refresh endpoint, `users.getProfile`, `users.messages.list`,
and `users.messages.get?format=raw`. Implementing these over `httpx` avoids a
large transitive dependency tree for a handful of calls, mirrors the M13
precedent (stdlib scrypt over a new hashing dependency), and keeps every Google
interaction behind our own ports so it is fully mockable in tests. If a concrete
future requirement genuinely cannot be met safely over `httpx`, adding the SDK
will be revisited as its own decision.

### 2. Authorization: installed-app **loopback** OAuth 2.0 flow

Authorization uses Google's installed-app loopback flow:

1. AEGIS+ binds a temporary HTTP listener to `127.0.0.1` on an **ephemeral** port.
2. It opens the user's **system browser** to Google's consent page, carrying a
   `state` nonce and the loopback `redirect_uri`.
3. Google redirects back to the loopback with an authorization code; the listener
   captures it and validates the `state` nonce (CSRF protection).
4. AEGIS+ exchanges the code for tokens at the token endpoint over `httpx`.

There is **no** manual copy/paste of authorization codes and **no** embedded
webview (`QWebEngineView`) — the consent page always runs in the user's real
browser. The listener is lifecycle-safe: it binds only to loopback, lives only
for one authorization, and is torn down on success, denial, timeout, error, and
process exit (`atexit`).

### 3. Isolation, secrets, and the auth boundary

- **Code isolation.** Domain types and three ports (`IGmailAuthFlow`,
  `IGmailTokenStore`, `IGmailGateway`) plus a dedup port
  (`IGmailSyncStateRepository`) live in `core`. The `httpx`/OAuth/filesystem
  adapters live in `infrastructure/integrations/gmail`. The Email Analysis
  engine, knowledge graph, and Copilot never import Gmail or Google types.
- **Secrets.** The OAuth **client secret** is read from an environment variable
  (`AEGIS_GMAIL_CLIENT_SECRET`), never a committed file. User **tokens** are
  stored in a single JSON file with owner-only permissions (0600) under
  `data/gmail/`, outside version control (covered by `.gitignore`). Tokens are
  never logged, returned by the API, shown in the UI, or placed in Copilot
  context.
- **Read-only scope.** `GmailSettings` validates at load time that the requested
  scope is exactly `gmail.readonly`; any other value is rejected.
- **Auth boundary.** All `/api/gmail/*` routes sit behind the M13
  `require_session` guard (the AEGIS+ application login). This is distinct from
  the Gmail OAuth identity, which only authorizes AEGIS+ to read the mailbox. The
  two are never merged.

### 4. Message seam and deduplication

Messages are fetched as raw RFC-822 (`format=raw`, base64url-decoded) and passed
straight to `EmailAnalysisService.analyze(raw_email)`, so the existing parser,
detection, IOC extraction, threat intelligence, correlation, event bus, graph,
analytics, SOC, and Copilot are all reused unchanged. Deduplication uses the
Gmail message id as the external identity, recorded in a minimal additive table
(`gmail_processed_messages`); repeated syncs never re-analyze a message.

## Consequences

**Positive**

- No new dependency; the frozen stack and all 7 Import Linter contracts hold.
- Google specifics are fully isolated behind ports and completely mockable, so
  the entire connector is tested with no network, Google account, or live OAuth.
- The user authorizes in their real browser (better trust and security than an
  embedded webview), with a CSRF-protected, ephemeral, lifecycle-safe listener.
- Zero duplication of the email pipeline; Gmail-derived intelligence appears in
  SOC, the graph, analytics, and Copilot automatically.

**Trade-offs / limitations**

- Implementing OAuth and the REST calls ourselves means we own that code
  (kept intentionally small). SDK conveniences (auto-retry, pagination helpers)
  are not used; for a bounded, manual, single-user connector this is acceptable.
- The loopback flow needs a momentarily-open localhost listener. It is bound to
  `127.0.0.1` on an ephemeral port and torn down immediately, minimizing exposure.
- Live OAuth requires network access to Google and a configured Desktop OAuth
  client; automated tests therefore mock Google entirely, and real-world OAuth is
  a documented manual validation step.

## Alternatives considered

- **`google-api-python-client` / `google-auth`:** rejected — a large new
  dependency tree for a small, stable surface; inconsistent with the project's
  dependency discipline. Revisit only if a concrete need cannot be met over httpx.
- **Manual copy/paste (out-of-band) OAuth:** rejected by requirement — poorer UX;
  the loopback flow returns the user to AEGIS+ automatically.
- **Embedded webview (`QWebEngineView`) consent:** rejected by requirement and on
  security grounds — users should authenticate to Google in their real browser,
  and Google discourages embedded webviews for OAuth.
- **Storing tokens in the database or config:** rejected — secrets do not belong
  in ordinary tables or committed config; a 0600 file outside the repo is simpler
  and safer for a single-user desktop app.
- **A Gmail-specific analyzer/graph/Copilot skill:** rejected by requirement and
  architecture — Gmail is only a source; all intelligence flows through the
  existing pipeline.

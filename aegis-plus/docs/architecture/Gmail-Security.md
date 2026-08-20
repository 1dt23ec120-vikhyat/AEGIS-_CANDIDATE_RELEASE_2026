# AEGIS+ Gmail Connector — Setup, Security & Troubleshooting (M14)

This guide covers Google Cloud configuration, local credential setup, the
read-only scope, token security, synchronization and disconnect behaviour, and
troubleshooting. Architecture and rationale are in
`docs/architecture/Gmail-Integration.md` and ADR-0004.

## Google Cloud setup (one-time, by the operator)

The AEGIS+ Gmail Google Cloud project is configured with:

1. A Google Cloud project.
2. The **Gmail API** enabled.
3. An **OAuth consent screen** (external audience) with a test user.
4. A **Desktop** OAuth client (installed-app flow).
5. The **`gmail.readonly`** scope.
6. Desktop OAuth credentials downloaded locally (client id + client secret).

AEGIS+ uses the **installed-app loopback** flow, so the Desktop OAuth client is
the correct client type. No fixed redirect URI needs registering for the loopback
flow; Google permits `http://127.0.0.1:<ephemeral-port>/` for Desktop clients.

## Local credential configuration

Credentials live **outside** the repository and are supplied through AEGIS+'s
existing configuration/environment conventions:

- **Client id** — not a secret. Set either:
  - environment: `AEGIS_GMAIL_CLIENT_ID`, or
  - `config/gmail.yaml` → `gmail.client_id`.
- **Client secret** — a secret. Set the environment variable named by
  `gmail.client_secret_env` (default **`AEGIS_GMAIL_CLIENT_SECRET`**). Never put
  the client secret in a committed file.

Example (shell):

```
export AEGIS_GMAIL_CLIENT_ID="<your-desktop-client-id>.apps.googleusercontent.com"
export AEGIS_GMAIL_CLIENT_SECRET="<your-desktop-client-secret>"
```

Other tunables in `config/gmail.yaml`: `scope` (must stay read-only),
`default_query` (default `in:inbox`), `max_list_results` (default 25; the initial
sync default of 50 is applied by the connector), `loopback_timeout_seconds`, and
`request_timeout_seconds`.

## Scope

AEGIS+ requests **only** `https://www.googleapis.com/auth/gmail.readonly`.
`GmailSettings` validates this at load time and rejects any broader scope. AEGIS+
never sends, deletes, moves, labels, marks-read, or otherwise modifies mail.

## Token security

- Access and refresh tokens are stored in a single JSON file with **owner-only
  permissions (0600)** at `data/gmail/tokens.json`, outside version control.
- `.gitignore` covers `data/gmail/`, `*token*.json`, and common credential file
  names, so tokens and secrets are never committed.
- Tokens are **never** logged, returned by any API response, shown in the UI, or
  placed in Copilot context. Error messages are user-safe and never include token
  material, authorization codes, stack traces, or internal paths.
- Disconnect deletes the token file and clears sync state.

## Using the connector

1. Sign in to AEGIS+ (application login).
2. Open **Gmail Intelligence** (sidebar → Integrations).
3. Click **Connect Gmail**. Your system browser opens Google's consent page.
4. Approve **read-only** access. The browser redirects to the local loopback and
   AEGIS+ detects completion automatically.
5. AEGIS+ shows **Gmail Connected** with your account address and read-only badge.
6. Click **Sync Now** to fetch recent messages. Each new message flows through the
   existing email intelligence pipeline; results appear across SOC, the graph,
   analytics, and the Copilot.
7. Repeated **Sync Now** does not re-analyze already-processed messages.
8. Click **Disconnect Gmail** to stop and clear local authorization.

## Synchronization behaviour

- Manual **Sync Now** is the primary workflow. The default bound is the 50 most
  recent messages (configurable).
- Deduplication is by Gmail message id; repeated syncs skip processed messages.
- Statistics reported: retrieved, analyzed, duplicates, malicious, suspicious,
  benign, errors, and last-sync time.
- **Automatic monitoring is OFF** in M14 (shown in the UI). A clean seam exists
  for a future conservative poller; no background daemon is included.

## Disconnect behaviour

Disconnect clears local tokens and sync state and returns the UI to the
disconnected state. Previously generated AEGIS+ intelligence (threats, incidents,
graph, scans) is **retained**.

## Troubleshooting

| Symptom | Likely cause | Resolution |
|--------|--------------|------------|
| "Gmail OAuth client is not configured." | Missing client id / secret | Set `AEGIS_GMAIL_CLIENT_ID` and `AEGIS_GMAIL_CLIENT_SECRET`. |
| Browser does not open | No default browser / headless host | Open AEGIS+ on a desktop with a browser; the loopback flow requires one. |
| "Gmail authorization was denied." | Consent declined | Re-run Connect and approve read-only access. |
| "Timed out waiting for Gmail authorization." | Consent not completed in time | Re-run Connect; complete consent within the timeout. |
| "Your Gmail authorization has expired. Please reconnect." | Refresh token revoked/expired | Disconnect, then Connect again. |
| "AEGIS+ could not reach Gmail." | Network / API unavailable | Check connectivity; retry later. |
| Sync shows errors on some messages | Individual malformed messages | Other messages still process; errors are counted, not fatal. |
| No account connected on Sync | Not connected | Connect Gmail first. |

## Limitations (M14)

- Single Gmail account per installation (single-user model).
- Manual synchronization only; automatic monitoring is a documented future seam.
- Read-only: AEGIS+ cannot act on mail.
- Live OAuth requires network access to Google and a configured Desktop OAuth
  client; automated tests mock Google entirely.

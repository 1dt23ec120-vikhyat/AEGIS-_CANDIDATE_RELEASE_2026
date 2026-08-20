# ADR-0003 — Local Authentication, scrypt Hashing, and Server-Side Sessions

- **Status:** Accepted (M13)
- **Context date:** M13
- **Deciders:** Architecture review (gated milestone approvals)

## Context

M13 introduces authentication and secure application entry. AEGIS+ is a
single-user-per-installation desktop security application: there is exactly one
local account, and no multi-user administration, RBAC, SSO, LDAP, cloud identity,
or multi-tenancy is in scope. The requirement is a professional, secure local
account with registration, login, session management, logout, protected API
routes, and a production-quality authentication UI.

Three decisions needed recording: how passwords are hashed, how sessions are
represented, and where the authentication boundary is enforced. Each had to fit
the frozen stack (Python 3.12, PySide6, FastAPI, SQLAlchemy + Alembic, SQLite)
without introducing distributed-systems infrastructure inappropriate for a local
desktop app, and without adding an unjustified dependency.

## Decision

### 1. Password hashing — stdlib `hashlib.scrypt`

Passwords are hashed with the standard library's memory-hard `hashlib.scrypt`.
No bcrypt/argon2/passlib dependency exists in the frozen stack, and scrypt is a
professionally accepted, memory-hard password-hashing function already available
in the Python standard library. Using it satisfies the security requirement with
**zero new dependencies**, honouring the project's dependency discipline (prefer
the existing stack; justify any addition before making it).

- Parameters: `n = 2^14`, `r = 8`, `p = 1`, 16-byte random per-account salt,
  32-byte derived key.
- Storage format is a single opaque, self-describing string:
  `scrypt$n$r$p$salt_b64$hash_b64`, so verification needs only the stored value
  and the candidate password.
- Verification is constant-time (`hmac.compare_digest`) and never raises on a
  malformed stored hash — it returns `False`.

The `IPasswordHasher` port keeps the algorithm behind an interface, so a future
change (e.g. to argon2, should it enter the stack) is a one-adapter change with
no impact on domain, services, or API.

### 2. Sessions — server-side opaque bearer tokens

On successful login the authentication service creates a session row with a
high-entropy random token (`secrets.token_urlsafe(32)`) and an expiry
(`created_at + TTL`, default 12 hours). The token is returned to the client,
which sends it as `Authorization: Bearer <token>` on every subsequent request. A
FastAPI dependency validates the token, checks expiry (deleting expired
sessions), and resolves the current user. Logout deletes the session row.

This is the simplest secure model that fits an embedded-localhost FastAPI backend
paired with a PySide6 client. No JWT, no Redis, no distributed session store —
those would be unjustified complexity for a single local user. Sessions persist
in the existing SQLite database via one additive migration, so they survive
navigation within the app and are invalidated deterministically on logout or
expiry.

### 3. Enforcement at the API boundary

The authentication boundary is enforced at the API, not merely by hiding UI
navigation. Every analyst-facing router (URL, email, file, threats, incidents,
SOC, graph, analytics, copilot) is mounted behind a `require_session`
dependency; only the health probe and the auth endpoints themselves are open. An
unauthenticated request to any protected route receives `401`, regardless of the
UI. The desktop client attaches the bearer token to all calls and, on a `401`,
routes the analyst back to login with a session-expired notice.

### 4. Security UX — no account enumeration

Login failures are generic (`"Invalid username or password."`) whether the
identifier is unknown or the password is wrong. Login runs a dummy hash
verification even when no account matches, to keep response timing uniform. The
password hash is never returned by any endpoint, never logged, and never placed
in UI state or debug metadata. The single-account constraint is enforced in the
application service.

## Consequences

**Positive**

- No new dependency; the frozen stack is preserved.
- Clean layering: `IPasswordHasher` / `IUserRepository` /
  `IAuthSessionRepository` ports in core, concrete adapters in infrastructure,
  orchestration in a services-layer `AuthenticationService`, HTTP surface in
  application. All 7 Import Linter contracts remain satisfied.
- The boundary is real (API-enforced), so hiding or bypassing UI navigation
  cannot reach protected data.
- Sessions are simple, auditable, and invalidated deterministically.

**Trade-offs / limitations**

- scrypt parameters are tuned for a desktop login; they are a compile-time
  constant, adjustable if hardware assumptions change. Because the hash string is
  self-describing, already-stored hashes continue to verify after a parameter
  change (new hashes use the new cost).
- Server-side sessions require a database round-trip per protected request. For a
  local single-user app this cost is negligible and buys deterministic
  revocation (logout truly invalidates).
- The model is intentionally **not** an enterprise identity system. Multi-user,
  RBAC, SSO, and federation are explicitly out of scope and would require a
  separate, larger design.

## Alternatives considered

- **bcrypt / argon2 / passlib:** rejected — each is a new third-party dependency,
  and scrypt in the stdlib already provides memory-hard hashing. argon2 is
  excellent, but adding it was not justified given a capable stdlib option.
- **PBKDF2 (`hashlib.pbkdf2_hmac`):** acceptable and also stdlib, but not
  memory-hard; scrypt is the stronger choice against GPU/ASIC attacks at
  comparable integration cost.
- **JWT / stateless tokens:** rejected — statelessness's main benefit is avoiding
  server-side session lookups across distributed nodes, which does not apply to a
  single local backend; it also complicates deterministic logout/revocation.
- **OS keychain / platform credential store:** rejected for the account secret —
  it would couple the app to per-OS credential APIs and does not fit the
  single-file, portable SQLite model; the password hash in the app database is
  sufficient and portable.
- **UI-only gating (no API enforcement):** rejected — it would leave protected
  data reachable by any client that skips the UI, violating security-by-design.

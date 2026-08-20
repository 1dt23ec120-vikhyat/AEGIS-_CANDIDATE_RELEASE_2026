# AEGIS+ Authentication Architecture (M13)

## Purpose

AEGIS+ is a single-user-per-installation desktop security application. M13 adds a
professional local authentication system: registration, login, session
management, logout, API-level route protection, and a production-quality
authentication UI. This document describes the architecture; the key design
decisions are recorded in ADR-0003.

This is deliberately **not** an enterprise identity system — no multi-user
administration, RBAC, SSO, LDAP, cloud identity, OAuth login, or multi-tenancy.
There is exactly one local account.

## Flow

```
First launch:   AEGIS+ → Authentication (Register) → account created → Login → SOC Command Center
Subsequent:     AEGIS+ → Authentication (Login) → SOC Command Center
Logout:         SOC Command Center → Logout → session invalidated → Login
```

Request path (unchanged architecture, extended):

```
PySide6 Authentication UI
      ↓  (BackendClient)
FastAPI Authentication API  (/api/auth/*)
      ↓
AuthenticationService  (services layer)
      ↓  (IUserRepository / IAuthSessionRepository via a unit of work)
SQLAlchemy repositories → SQLite
```

The UI never touches SQLite or authentication logic directly; it reaches the
backend only through `BackendClient` and the REST API.

## Layering

The feature is spread across the existing Clean Architecture layers, and all
seven Import Linter contracts remain satisfied.

| Layer | Auth additions |
|-------|----------------|
| **core** | `domain/auth.py` (`User`, `AuthSession`, `AuthenticatedUser`); ports `IPasswordHasher`, `IUserRepository`, `IAuthSessionRepository`; `security/auth_policy.py` (validation + normalization). Framework-free. |
| **infrastructure** | `security/password_hasher.py` (`ScryptPasswordHasher`, stdlib only); `database/models.py` rows `UserAccountRow`, `AuthSessionRow`; `repositories/auth_repository.py` (SQLAlchemy repositories). |
| **services** | `auth/service.py` (`AuthenticationService`): register / login / logout / current-user / purge-expired, orchestrating the repositories, hasher, and validation policy through a caller-supplied unit of work. |
| **application** | `api/auth.py` (router + `require_session` dependency + DTOs); protected routers mounted behind the guard in `api/app.py`; container wiring (`_build_auth`); one Alembic migration. |
| **ui** | `viewmodels/auth.py` (`AuthViewModel`); `pages/auth_window.py` (`AuthWindow`); `components/auth_fields.py`; `BackendClient` auth methods; `shell/auth_flow.py` (`DesktopAuthFlow`); logout action in the shell top bar. |

## Domain model

- **User** — the single local account: id, full name, username, email, password
  hash, timestamps. Never holds a plaintext password.
- **AuthSession** — an authenticated session: opaque token, user id, created/expiry
  timestamps; `is_expired()` is timezone-safe (a naive stored expiry is
  interpreted as UTC).
- **AuthenticatedUser** — the safe, hash-free projection returned to the API/UI.

## Password hashing

Passwords are hashed with stdlib `hashlib.scrypt` (memory-hard, no new
dependency). Per-account 16-byte random salt; parameters `n=2^14, r=8, p=1`;
32-byte derived key. Stored as a self-describing string
`scrypt$n$r$p$salt_b64$hash_b64`. Verification is constant-time and returns
`False` (never raises) for a malformed stored hash. The algorithm sits behind
`IPasswordHasher`, so it can be swapped without touching callers. See ADR-0003.

## Sessions

Login creates a session row (`secrets.token_urlsafe(32)`, expiry = now + TTL,
default 12h). The client presents it as `Authorization: Bearer <token>`. The
`require_session` dependency validates the token, deletes and rejects expired
sessions, and resolves the current user. Logout deletes the session row. Sessions
live in the existing SQLite database (one additive migration); no JWT/Redis. See
ADR-0003.

## API

| Method & path | Auth | Purpose | Codes |
|---------------|------|---------|-------|
| `GET /api/auth/status` | open | First-launch hint (`account_exists`) | 200 |
| `POST /api/auth/register` | open | Create the single account | 201 / 409 / 422 |
| `POST /api/auth/login` | open | Authenticate, issue a session | 200 / 401 |
| `GET /api/auth/me` | session | Current authenticated user | 200 / 401 |
| `POST /api/auth/logout` | session | Invalidate the session | 204 |

Every other analyst-facing router (analysis, email, file, threats, incidents,
soc, graph, analytics, copilot) is mounted behind `require_session`. Only the
health probe and the auth endpoints are open. Password hashes are never returned;
errors are safe and generic.

## Startup and the desktop flow

`main.py` bootstraps the backend, then `run_desktop` shows the authentication
window first. `DesktopAuthFlow` owns the lifecycle:

- shows `AuthWindow`; on `authenticated`, builds and shows the `MainWindow`
  (SOC Command Center) and starts its services;
- on **logout**, invalidates the session, tears down the shell, and returns to
  the auth window;
- on a backend **401** (session expired), routes back to the auth window with a
  session-expired notice.

The shell is never constructed until authentication succeeds. The
`BackendHealthPoller` is stopped and drained on teardown so no worker signal
fires into a destroyed window (clean Qt shutdown).

## Security UX

- Generic `"Invalid username or password."` for all login failures; a dummy hash
  verification runs even when the account is absent to keep timing uniform (no
  account enumeration).
- Passwords are never stored in plaintext, never returned, never logged, and
  never placed in UI state or debug metadata.
- The single-account constraint is enforced in the service.

## Testing

Backend: registration (success/validation/duplicate/invalid email/weak/mismatch),
login (success/wrong password/unknown/generic errors/case-insensitive),
session (`/me`, protected access, unauthenticated rejection, expiry), logout
invalidation, and the guarantees that hashes are never returned. UI: window
rendering, login/register switching, validation, password visibility, successful
login/registration navigation, backend-failure and session-expired states, logout
navigation, protected-shell handoff, keyboard behaviour, and clean Qt shutdown.

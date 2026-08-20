"""Authentication application service (M13).

Orchestrates registration, login, session validation, and logout for the single
local AEGIS+ account. It composes the auth repositories (via a caller-supplied
session-scoped factory), the password hasher, and the core validation policy. It
holds no web or UI concerns and never logs secrets.

Security posture:
- Passwords are hashed with the injected hasher; plaintext is never stored,
  returned, or logged.
- Login failures are generic (``INVALID_CREDENTIALS``) and do not reveal whether
  an account or identifier exists.
- The single-account constraint is enforced here: registration is refused once an
  account exists.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from core.domain.auth import AuthenticatedUser, AuthSession, User
from core.interfaces.auth_repository import IAuthSessionRepository, IUserRepository
from core.interfaces.logger import ILogger
from core.interfaces.password_hasher import IPasswordHasher
from core.security.auth_policy import (
    normalize_identifier,
    normalize_registration,
    validate_registration,
)

_TOKEN_BYTES = 32
_DEFAULT_SESSION_TTL_MINUTES = 720  # 12 hours
# A well-formed but non-matching hash used to keep login timing uniform whether or
# not an account exists (mitigates account-enumeration via response time).
_DUMMY_HASH = (
    "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==" "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)


@dataclass(frozen=True, slots=True)
class AuthRepositories:
    """The auth repositories bound to one session/unit of work."""

    users: IUserRepository
    sessions: IAuthSessionRepository


# A unit of work: opens a session, yields the bound repositories, and commits if
# the callable returns normally (rolls back on exception). Provided by the
# composition root so the service stays free of SQLAlchemy.
AuthUnitOfWork = Callable[[Callable[[AuthRepositories], object]], object]


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    """Outcome of a registration attempt."""

    ok: bool
    user: AuthenticatedUser | None = None
    field_errors: dict[str, str] | None = None
    error_code: str = ""


@dataclass(frozen=True, slots=True)
class LoginResult:
    """Outcome of a login attempt."""

    ok: bool
    token: str = ""
    user: AuthenticatedUser | None = None
    expires_at: datetime | None = None
    error_code: str = ""


class AuthenticationService:
    """Registration, login, session validation, and logout."""

    def __init__(
        self,
        unit_of_work: AuthUnitOfWork,
        hasher: IPasswordHasher,
        logger: ILogger,
        *,
        session_ttl_minutes: int = _DEFAULT_SESSION_TTL_MINUTES,
    ) -> None:
        """Initialize the service.

        Args:
            unit_of_work: Runs a callable within a committed auth unit of work.
            hasher: Password hasher.
            logger: Structured logger (never receives secrets).
            session_ttl_minutes: Session lifetime in minutes.
        """
        self._uow = unit_of_work
        self._hasher = hasher
        self._logger = logger
        self._ttl = timedelta(minutes=session_ttl_minutes)

    # --- queries ---------------------------------------------------------

    def account_exists(self) -> bool:
        """Whether a local account has been registered."""
        return bool(self._uow(lambda repos: repos.users.account_exists()))

    # --- registration ----------------------------------------------------

    def register(
        self,
        *,
        full_name: str,
        username: str,
        email: str,
        password: str,
        confirm_password: str,
    ) -> RegistrationResult:
        """Register the single local account."""
        data = normalize_registration(
            full_name=full_name, username=username, email=email, password=password
        )
        outcome = validate_registration(data, confirm_password=confirm_password)
        if not outcome.ok:
            return RegistrationResult(
                ok=False, field_errors=outcome.errors, error_code="VALIDATION"
            )

        password_hash = self._hasher.hash(data.password)

        def op(repos: AuthRepositories) -> RegistrationResult:
            if repos.users.account_exists():
                return RegistrationResult(ok=False, error_code="ACCOUNT_EXISTS")
            conflict = repos.users.find_conflict(username=data.username, email=data.email)
            if conflict is not None:
                return RegistrationResult(
                    ok=False,
                    error_code="ACCOUNT_EXISTS",
                    field_errors={conflict: f"That {conflict} is already registered."},
                )
            user = User.create(
                full_name=data.full_name,
                username=data.username,
                email=data.email,
                password_hash=password_hash,
            )
            repos.users.add(user)
            self._logger.info("auth: account registered", username=data.username)
            return RegistrationResult(ok=True, user=AuthenticatedUser.of(user))

        result = self._uow(op)
        assert isinstance(result, RegistrationResult)
        return result

    # --- login / logout --------------------------------------------------

    def login(self, *, identifier: str, password: str) -> LoginResult:
        """Authenticate and create a session. Errors are generic."""
        needle = normalize_identifier(identifier)
        now = datetime.now(UTC)
        expires_at = now + self._ttl
        token = secrets.token_urlsafe(_TOKEN_BYTES)

        def op(repos: AuthRepositories) -> LoginResult:
            user = repos.users.get_by_identifier(needle)
            # Always run a verification to reduce timing signal, even if absent.
            reference_hash = user.password_hash if user is not None else _DUMMY_HASH
            valid = self._hasher.verify(password, reference_hash)
            if user is None or not valid:
                return LoginResult(ok=False, error_code="INVALID_CREDENTIALS")
            repos.sessions.add(
                AuthSession(token=token, user_id=user.id, created_at=now, expires_at=expires_at)
            )
            self._logger.info("auth: login succeeded", username=user.username)
            return LoginResult(
                ok=True,
                token=token,
                user=AuthenticatedUser.of(user),
                expires_at=expires_at,
            )

        result = self._uow(op)
        assert isinstance(result, LoginResult)
        return result

    def logout(self, token: str) -> None:
        """Invalidate a session (no-op if unknown)."""

        def op(repos: AuthRepositories) -> None:
            repos.sessions.delete(token)

        self._uow(op)

    # --- session validation ---------------------------------------------

    def current_user(self, token: str) -> AuthenticatedUser | None:
        """Return the authenticated user for a valid, unexpired session.

        Expired sessions are deleted as a side effect and treated as absent.
        """
        if not token:
            return None
        now = datetime.now(UTC)

        def op(repos: AuthRepositories) -> AuthenticatedUser | None:
            session = repos.sessions.get(token)
            if session is None:
                return None
            if session.is_expired(now=now):
                repos.sessions.delete(token)
                return None
            user = repos.users.get_by_id(session.user_id)
            return AuthenticatedUser.of(user) if user is not None else None

        result = self._uow(op)
        assert result is None or isinstance(result, AuthenticatedUser)
        return result

    def purge_expired(self) -> int:
        """Delete all expired sessions; return how many were removed."""
        now_iso = datetime.now(UTC).isoformat()

        def op(repos: AuthRepositories) -> int:
            return repos.sessions.delete_expired(before_iso=now_iso)

        result = self._uow(op)
        return int(result) if isinstance(result, int) else 0

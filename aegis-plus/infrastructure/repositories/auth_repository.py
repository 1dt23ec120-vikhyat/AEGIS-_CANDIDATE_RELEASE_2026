"""Authentication repositories (M13).

SQLAlchemy-backed implementations of the auth persistence ports. Each is bound to
a session supplied by the caller (a fresh short-lived session per operation, from
the shared session factory). They map between domain types and ORM rows and
expose only domain-oriented operations, so SQLAlchemy never leaks to callers.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from core.domain.auth import AuthSession, User
from core.interfaces.auth_repository import IAuthSessionRepository, IUserRepository
from infrastructure.database.models import AuthSessionRow, UserAccountRow


class SqlAlchemyUserRepository(IUserRepository):
    """User account persistence for the single-account model."""

    def __init__(self, session: Session) -> None:
        """Initialize with an active session."""
        self._session = session

    def account_exists(self) -> bool:
        """Whether any local account row exists."""
        count = self._session.scalar(select(func.count()).select_from(UserAccountRow))
        return bool(count)

    def add(self, user: User) -> User:
        """Persist the account row."""
        self._session.add(_to_user_row(user))
        self._session.flush()
        return user

    def get_by_identifier(self, identifier: str) -> User | None:
        """Return the account matching a username or email (case-insensitive)."""
        needle = identifier.strip().lower()
        stmt = select(UserAccountRow).where(
            (func.lower(UserAccountRow.username) == needle)
            | (func.lower(UserAccountRow.email) == needle)
        )
        row = self._session.scalars(stmt).first()
        return _to_user(row) if row is not None else None

    def get_by_id(self, user_id: str) -> User | None:
        """Return the account by id."""
        row = self._session.get(UserAccountRow, user_id)
        return _to_user(row) if row is not None else None

    def find_conflict(self, *, username: str, email: str) -> str | None:
        """Return ``"username"`` or ``"email"`` if either already exists."""
        uname = username.strip().lower()
        mail = email.strip().lower()
        row = self._session.scalars(
            select(UserAccountRow).where(
                (func.lower(UserAccountRow.username) == uname)
                | (func.lower(UserAccountRow.email) == mail)
            )
        ).first()
        if row is None:
            return None
        if row.username.lower() == uname:
            return "username"
        return "email"


class SqlAlchemyAuthSessionRepository(IAuthSessionRepository):
    """Authenticated-session persistence."""

    def __init__(self, session: Session) -> None:
        """Initialize with an active session."""
        self._session = session

    def add(self, session: AuthSession) -> AuthSession:
        """Persist a new session row."""
        self._session.add(
            AuthSessionRow(
                token=session.token,
                user_id=session.user_id,
                created_at=session.created_at,
                expires_at=session.expires_at,
            )
        )
        self._session.flush()
        return session

    def get(self, token: str) -> AuthSession | None:
        """Return the session for ``token``."""
        row = self._session.get(AuthSessionRow, token)
        if row is None:
            return None
        return AuthSession(
            token=row.token,
            user_id=row.user_id,
            created_at=row.created_at,
            expires_at=row.expires_at,
        )

    def delete(self, token: str) -> None:
        """Delete the session for ``token``."""
        self._session.execute(delete(AuthSessionRow).where(AuthSessionRow.token == token))

    def delete_expired(self, *, before_iso: str) -> int:
        """Delete sessions expiring at or before ``before_iso``."""
        cutoff = datetime.fromisoformat(before_iso)
        result = self._session.execute(
            delete(AuthSessionRow).where(AuthSessionRow.expires_at <= cutoff)
        )
        return int(result.rowcount or 0)  # type: ignore[attr-defined]


def _to_user_row(user: User) -> UserAccountRow:
    return UserAccountRow(
        id=user.id,
        created_at=user.created_at,
        updated_at=user.updated_at,
        full_name=user.full_name,
        username=user.username,
        email=user.email,
        password_hash=user.password_hash,
    )


def _to_user(row: UserAccountRow) -> User:
    return User(
        id=row.id,
        full_name=row.full_name,
        username=row.username,
        email=row.email,
        password_hash=row.password_hash,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )

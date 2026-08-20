"""Authentication repository ports (M13).

Persistence contracts for the single-user account model and its sessions. These
return domain types (`User`, `AuthSession`), never ORM rows, and are implemented
in infrastructure. The user repository models the single-account constraint
directly: there is at most one account, looked up by username or email for
login.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.auth import AuthSession, User


class IUserRepository(ABC):
    """Persistence for the single local AEGIS+ account."""

    @abstractmethod
    def account_exists(self) -> bool:
        """Whether a local account has been registered."""

    @abstractmethod
    def add(self, user: User) -> User:
        """Persist the account. Raises if one already exists."""

    @abstractmethod
    def get_by_identifier(self, identifier: str) -> User | None:
        """Return the account matching a username or email, or ``None``.

        The lookup is case-insensitive on both fields so that login accepts the
        identifier as the user typed it during registration.
        """

    @abstractmethod
    def get_by_id(self, user_id: str) -> User | None:
        """Return the account by id, or ``None``."""

    @abstractmethod
    def find_conflict(self, *, username: str, email: str) -> str | None:
        """Return ``"username"`` or ``"email"`` if either is already taken.

        Returns ``None`` when neither collides with the existing account.
        """


class IAuthSessionRepository(ABC):
    """Persistence for authenticated sessions."""

    @abstractmethod
    def add(self, session: AuthSession) -> AuthSession:
        """Persist a new session."""

    @abstractmethod
    def get(self, token: str) -> AuthSession | None:
        """Return the session for ``token``, or ``None`` if absent."""

    @abstractmethod
    def delete(self, token: str) -> None:
        """Delete the session for ``token`` (no-op if absent)."""

    @abstractmethod
    def delete_expired(self, *, before_iso: str) -> int:
        """Delete sessions whose expiry is at or before ``before_iso``.

        Returns the number of sessions removed. ``before_iso`` is an ISO-8601
        UTC timestamp string, keeping this port free of any datetime coupling in
        signatures shared with the web layer.
        """

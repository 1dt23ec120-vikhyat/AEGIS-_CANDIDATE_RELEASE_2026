"""Authentication domain (M13).

Framework-free domain types for the single-user local account model. ``User`` is
the one local AEGIS+ account; ``AuthSession`` is an authenticated session issued
on login and invalidated on logout or expiry. These carry no persistence or web
concerns — mapping to rows lives in infrastructure, and the hashing algorithm
lives behind the :class:`~core.interfaces.password_hasher.IPasswordHasher` port.

The domain never holds a plaintext password: a ``User`` stores only an opaque
password-hash string whose internal format is owned by the hasher.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class User:
    """The single local AEGIS+ account.

    ``password_hash`` is an opaque, self-describing hash string produced by the
    password hasher; the domain never sees or stores the plaintext password.
    """

    id: str
    full_name: str
    username: str
    email: str
    password_hash: str
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def create(
        *,
        full_name: str,
        username: str,
        email: str,
        password_hash: str,
    ) -> User:
        """Create a new user with a generated id and current timestamps."""
        now = datetime.now(UTC)
        return User(
            id=uuid.uuid4().hex,
            full_name=full_name,
            username=username,
            email=email,
            password_hash=password_hash,
            created_at=now,
            updated_at=now,
        )


@dataclass(frozen=True, slots=True)
class AuthSession:
    """An authenticated session bound to the local user.

    ``token`` is an opaque high-entropy secret presented by the client on each
    request. A session is valid until ``expires_at`` or until it is deleted on
    logout.
    """

    token: str
    user_id: str
    created_at: datetime
    expires_at: datetime

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """Whether the session has passed its expiry.

        Robust to a naive ``expires_at`` (some database drivers drop tzinfo on
        round-trip): a naive expiry is interpreted as UTC.
        """
        moment = now or datetime.now(UTC)
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return moment >= expiry


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """The safe projection of the authenticated user for API/UI responses.

    Deliberately omits the password hash so it can never be returned to a client.
    """

    id: str
    full_name: str
    username: str
    email: str

    @staticmethod
    def of(user: User) -> AuthenticatedUser:
        """Project a :class:`User` to its safe, hash-free representation."""
        return AuthenticatedUser(
            id=user.id,
            full_name=user.full_name,
            username=user.username,
            email=user.email,
        )

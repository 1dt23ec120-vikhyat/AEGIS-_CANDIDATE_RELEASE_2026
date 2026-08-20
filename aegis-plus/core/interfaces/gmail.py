"""Gmail connector ports (M14).

Abstractions for the read-only Gmail connector, so the services and application
layers depend only on interfaces — never on httpx, Google, the filesystem, or the
OAuth mechanics. Concrete adapters live in infrastructure.

Three boundaries:
- :class:`IGmailAuthFlow` performs the installed-app loopback OAuth 2.0 flow and
  token refresh.
- :class:`IGmailTokenStore` persists the resulting credentials in a protected,
  out-of-repository location.
- :class:`IGmailGateway` reads messages from the Gmail REST API (list + fetch raw).

Keeping these separate preserves the boundary between AEGIS+ authentication and
Gmail OAuth, and keeps every network/secret concern injectable for tests.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.domain.gmail import GmailCredentials, GmailMessageRef, GmailRawMessage


class GmailConnectorError(Exception):
    """Base error for Gmail connector failures (never carries a secret)."""


class GmailAuthError(GmailConnectorError):
    """Raised when authorization or token refresh fails."""


class GmailApiError(GmailConnectorError):
    """Raised when a Gmail REST call fails."""


class IGmailAuthFlow(ABC):
    """Performs the loopback OAuth 2.0 authorization and token refresh."""

    @abstractmethod
    def authorize(self) -> GmailCredentials:
        """Run the installed-app loopback flow and return fresh credentials.

        Opens the system browser to Google's consent page, receives the
        authorization code on a temporary ``127.0.0.1`` callback, and exchanges
        it for tokens. Blocks until the user completes or cancels consent, or the
        wait times out.

        Raises:
            GmailAuthError: If consent is denied, times out, or the exchange
                fails.
        """

    @abstractmethod
    def refresh(self, credentials: GmailCredentials) -> GmailCredentials:
        """Return refreshed credentials using the stored refresh token.

        Raises:
            GmailAuthError: If the refresh token is invalid or revoked.
        """


class IGmailTokenStore(ABC):
    """Persists Gmail OAuth credentials in a protected local store."""

    @abstractmethod
    def load(self) -> GmailCredentials | None:
        """Return stored credentials, or ``None`` if not connected."""

    @abstractmethod
    def save(self, credentials: GmailCredentials) -> None:
        """Persist credentials with owner-only permissions."""

    @abstractmethod
    def clear(self) -> None:
        """Remove any stored credentials (disconnect)."""


class IGmailGateway(ABC):
    """Read-only access to the Gmail REST API."""

    @abstractmethod
    def profile_email(self, credentials: GmailCredentials) -> str:
        """Return the connected account's email address."""

    @abstractmethod
    def list_messages(
        self, credentials: GmailCredentials, *, query: str, max_results: int
    ) -> tuple[GmailMessageRef, ...]:
        """List message references matching a Gmail search ``query``."""

    @abstractmethod
    def fetch_raw(self, credentials: GmailCredentials, message_id: str) -> GmailRawMessage:
        """Fetch one message as raw RFC-822 text (``format=raw``)."""

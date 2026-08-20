"""Gmail REST gateway (M14).

Read-only access to the Gmail API over ``httpx`` — no Google SDK. Implements only
what the connector needs: the account profile, a message list for a search query,
and fetching a single message as raw RFC-822 text (``format=raw``), which the
existing Email Analysis pipeline consumes directly.

The gateway performs no token refresh; it accepts already-valid credentials and
raises :class:`GmailAuthError` on a 401 so the caller can refresh and retry. No
token or secret is ever logged.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

import httpx

from core.domain.gmail import GmailCredentials, GmailMessageRef, GmailRawMessage
from core.interfaces.gmail import GmailApiError, GmailAuthError, IGmailGateway


class HttpxGmailGateway(IGmailGateway):
    """Gmail read-only REST client."""

    def __init__(self, *, api_base_url: str, timeout_seconds: float = 30.0) -> None:
        """Initialize the gateway.

        Args:
            api_base_url: Gmail API base URL.
            timeout_seconds: Per-request timeout.
        """
        self._base = api_base_url.rstrip("/")
        self._timeout = timeout_seconds

    def profile_email(self, credentials: GmailCredentials) -> str:
        """Return the connected account's email address."""
        data = self._get(credentials, "/gmail/v1/users/me/profile")
        return str(data.get("emailAddress", ""))

    def list_messages(
        self, credentials: GmailCredentials, *, query: str, max_results: int
    ) -> tuple[GmailMessageRef, ...]:
        """List message references matching a Gmail search ``query``."""
        listing = self._get(
            credentials,
            "/gmail/v1/users/me/messages",
            params={"q": query, "maxResults": max_results},
        )
        messages = listing.get("messages") or []
        refs: list[GmailMessageRef] = []
        for entry in messages[:max_results]:
            message_id = str(entry.get("id", ""))
            if not message_id:
                continue
            refs.append(self._metadata_ref(credentials, message_id))
        return tuple(refs)

    def fetch_raw(self, credentials: GmailCredentials, message_id: str) -> GmailRawMessage:
        """Fetch one message as raw RFC-822 text."""
        data = self._get(
            credentials,
            f"/gmail/v1/users/me/messages/{message_id}",
            params={"format": "raw"},
        )
        raw_b64 = str(data.get("raw", ""))
        try:
            raw_bytes = base64.urlsafe_b64decode(raw_b64)
        except (binascii.Error, ValueError) as exc:
            raise GmailApiError("Gmail returned an undecodable raw message.") from exc
        return GmailRawMessage(
            message_id=message_id,
            raw=raw_bytes.decode("utf-8", errors="replace"),
        )

    # --- internals -------------------------------------------------------

    def _metadata_ref(self, credentials: GmailCredentials, message_id: str) -> GmailMessageRef:
        data = self._get(
            credentials,
            f"/gmail/v1/users/me/messages/{message_id}",
            params={
                "format": "metadata",
                "metadataHeaders": ["Subject", "From", "Date"],
            },
        )
        headers = {
            str(h.get("name", "")).lower(): str(h.get("value", ""))
            for h in (data.get("payload", {}) or {}).get("headers", [])
        }
        return GmailMessageRef(
            message_id=message_id,
            thread_id=str(data.get("threadId", "")),
            snippet=str(data.get("snippet", "")),
            subject=headers.get("subject", ""),
            sender=headers.get("from", ""),
            received_at=headers.get("date", ""),
        )

    def _get(
        self,
        credentials: GmailCredentials,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = httpx.get(
                f"{self._base}{path}",
                params=params,
                headers={"Authorization": f"Bearer {credentials.access_token}"},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise GmailApiError("Could not reach the Gmail API.") from exc
        if response.status_code == httpx.codes.UNAUTHORIZED:
            raise GmailAuthError("Gmail credentials are expired or revoked.")
        if response.status_code != httpx.codes.OK:
            raise GmailApiError(f"Gmail API returned HTTP {response.status_code}.")
        body = response.json()
        if not isinstance(body, dict):
            raise GmailApiError("Unexpected Gmail API response shape.")
        return body

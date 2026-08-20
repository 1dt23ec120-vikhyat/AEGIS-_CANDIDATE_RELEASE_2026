"""File-based Gmail token store (M14).

Persists Gmail OAuth credentials in a single JSON file with owner-only
permissions (0600), in a location outside the repository. Tokens are secrets:
they are never logged, never returned by the API/UI, and never written anywhere
but this protected file. Disconnecting removes the file.

The store is deliberately simple (single local account, single file) and depends
on nothing but the standard library.
"""

from __future__ import annotations

import json
import os
import stat
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from core.domain.gmail import GmailCredentials
from core.interfaces.gmail import IGmailTokenStore

_OWNER_ONLY = stat.S_IRUSR | stat.S_IWUSR  # 0600


class FileGmailTokenStore(IGmailTokenStore):
    """Stores Gmail credentials as a 0600 JSON file outside the repository."""

    def __init__(self, token_path: Path) -> None:
        """Initialize with the absolute path to the token file."""
        self._path = token_path

    def load(self) -> GmailCredentials | None:
        """Return stored credentials, or ``None`` if not connected/unreadable."""
        if not self._path.exists():
            return None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return GmailCredentials(
                access_token=str(data["access_token"]),
                refresh_token=str(data["refresh_token"]),
                token_type=str(data.get("token_type", "Bearer")),
                scope=str(data.get("scope", "")),
                expires_at=datetime.fromisoformat(str(data["expires_at"])),
            )
        except (ValueError, KeyError, OSError):
            # A corrupt or unreadable token file is treated as "not connected"
            # rather than crashing the connector.
            return None

    def save(self, credentials: GmailCredentials) -> None:
        """Persist credentials, creating the parent dir and enforcing 0600."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "access_token": credentials.access_token,
            "refresh_token": credentials.refresh_token,
            "token_type": credentials.token_type,
            "scope": credentials.scope,
            "expires_at": _to_utc_iso(credentials.expires_at),
        }
        # Write with restrictive permissions from creation: open the fd with 0600
        # so the secret is never briefly world-readable.
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _OWNER_ONLY)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
        finally:
            # Enforce the mode even if the file pre-existed with a looser mode.
            with suppress(OSError):
                os.chmod(self._path, _OWNER_ONLY)

    def clear(self) -> None:
        """Remove any stored credentials (disconnect)."""
        with suppress(OSError):
            self._path.unlink(missing_ok=True)


def _to_utc_iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.isoformat()

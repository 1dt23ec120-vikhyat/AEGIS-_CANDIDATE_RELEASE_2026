"""Copilot session manager (M12 Phase 1).

An entirely in-memory store of conversation sessions. There is no persistence and
no database — sessions live only for the running application. Capacity is bounded
by LRU eviction, and each session's turn history is bounded per session, so
memory use is predictable.

The manager also holds the analyst focus state (what they are currently
investigating), which the UI updates and the Copilot reads for intent resolution
and context ranking.
"""

from __future__ import annotations

import uuid
from collections import OrderedDict
from datetime import UTC, datetime

from core.domain.copilot import ConversationTurn
from core.domain.copilot_session import CopilotSession, FocusState


def _now() -> str:
    return datetime.now(UTC).isoformat()


class SessionManager:
    """In-memory, LRU-bounded conversation session store."""

    def __init__(self, *, max_sessions: int = 100, max_turns: int = 20) -> None:
        """Initialize the session manager.

        Args:
            max_sessions: Maximum concurrent sessions before LRU eviction.
            max_turns: Maximum retained turns per session.
        """
        self._max_sessions = max_sessions
        self._max_turns = max_turns
        self._sessions: OrderedDict[str, CopilotSession] = OrderedDict()
        self._evictions = 0

    def get_or_create(self, session_id: str) -> CopilotSession:
        """Return the session for an id, creating it if absent."""
        if session_id and session_id in self._sessions:
            self._sessions.move_to_end(session_id)
            return self._sessions[session_id]

        new_id = session_id or str(uuid.uuid4())
        session = CopilotSession(session_id=new_id, created_at=_now(), updated_at=_now())
        self._store(session)
        return session

    def append_turn(self, session_id: str, turn: ConversationTurn) -> CopilotSession:
        """Append a turn to a session, returning the updated session."""
        session = self.get_or_create(session_id)
        updated = session.with_turn(turn, now=_now(), max_turns=self._max_turns)
        self._store(updated)
        return updated

    def update_focus(self, session_id: str, focus: FocusState) -> CopilotSession:
        """Update the focus state of a session."""
        session = self.get_or_create(session_id)
        updated = session.with_focus(focus, now=_now())
        self._store(updated)
        return updated

    def close(self, session_id: str) -> bool:
        """Close (delete) a session. Returns whether it existed."""
        return self._sessions.pop(session_id, None) is not None

    def get(self, session_id: str) -> CopilotSession | None:
        """Return a session without creating it."""
        session = self._sessions.get(session_id)
        if session is not None:
            self._sessions.move_to_end(session_id)
        return session

    def metrics(self) -> dict[str, float]:
        """Session store observability."""
        return {
            "active_sessions": float(len(self._sessions)),
            "evictions": float(self._evictions),
            "max_sessions": float(self._max_sessions),
        }

    def _store(self, session: CopilotSession) -> None:
        self._sessions[session.session_id] = session
        self._sessions.move_to_end(session.session_id)
        while len(self._sessions) > self._max_sessions:
            self._sessions.popitem(last=False)
            self._evictions += 1

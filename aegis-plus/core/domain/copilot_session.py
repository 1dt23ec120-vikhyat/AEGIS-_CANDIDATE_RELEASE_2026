"""AI Security Copilot session model (M12 Phase 1).

An entirely in-memory conversation session: the analyst's recent turns plus a
light focus state describing what they are currently investigating. There is no
persistence and no database — sessions live only for the running application and
are evicted when capacity is reached.

The focus state lets the Copilot resolve deictic questions ("why is *this*
malicious?") against the artifact/incident/campaign the analyst is looking at,
and lets context ranking prefer intelligence near the analyst's attention.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.domain.copilot import ConversationTurn


@dataclass(frozen=True, slots=True)
class FocusState:
    """What the analyst is currently working on (supplied by the UI).

    All fields are optional; the UI updates them as the analyst navigates. The
    Copilot reads them for intent resolution and context ranking but never
    depends on them being present.
    """

    current_artifact_id: str = ""
    current_incident_id: str = ""
    active_campaign_id: str = ""
    recent_graph_selections: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CopilotSession:
    """An in-memory conversation session.

    Immutable: the session manager replaces the stored session with an updated
    copy on each turn, keeping the value-object discipline used across the
    domain.
    """

    session_id: str
    turns: tuple[ConversationTurn, ...] = ()
    focus: FocusState = field(default_factory=FocusState)
    created_at: str = ""
    updated_at: str = ""

    def with_turn(self, turn: ConversationTurn, *, now: str, max_turns: int) -> CopilotSession:
        """Return a copy with ``turn`` appended, bounded to ``max_turns``."""
        combined = (*self.turns, turn)
        if len(combined) > max_turns:
            combined = combined[-max_turns:]
        return CopilotSession(
            session_id=self.session_id,
            turns=combined,
            focus=self.focus,
            created_at=self.created_at,
            updated_at=now,
        )

    def with_focus(self, focus: FocusState, *, now: str) -> CopilotSession:
        """Return a copy with an updated focus state."""
        return CopilotSession(
            session_id=self.session_id,
            turns=self.turns,
            focus=focus,
            created_at=self.created_at,
            updated_at=now,
        )

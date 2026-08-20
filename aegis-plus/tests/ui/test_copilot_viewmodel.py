"""Tests for the AI Security Copilot view-model (M12 Phase 2).

Backend calls run through an injected synchronous runner, so each ask completes
inline and assertions can inspect emitted signals and state directly. A fake
client returns canned :class:`CopilotResponse` objects — no network, no backend.
"""

from __future__ import annotations

import pytest

from core.domain.copilot import (
    Citation,
    ContextItem,
    CopilotResponse,
    GroundingViolation,
    PromptMetadata,
)
from tests.ui._async import SyncRunner
from ui.backend import BackendClient
from ui.viewmodels.copilot import ChatTurn, CopilotViewModel

pytestmark = pytest.mark.ui


def _response(
    *,
    answer: str = "Grounded answer.",
    session_id: str = "sess-1",
    available: bool = True,
    citations: tuple[Citation, ...] = (),
    violations: tuple[GroundingViolation, ...] = (),
) -> CopilotResponse:
    return CopilotResponse(
        answer=answer,
        citations=citations,
        session_id=session_id,
        available=available,
        grounding_violations=violations,
        prompt_metadata=PromptMetadata(skill_id="threat_investigation", provider="fake"),
        grounding_score=1.0,
    )


class _FakeClient(BackendClient):
    def __init__(self, response: CopilotResponse | None = None) -> None:
        super().__init__("http://127.0.0.1:9")
        self._response = response or _response()
        self.ask_calls: list[dict[str, str]] = []
        self.focus_calls: list[dict[str, str]] = []
        self.closed: list[str] = []

    def copilot_ask(
        self,
        question: str,
        *,
        session_id: str = "",
        artifact_id: str = "",
        incident_id: str = "",
        campaign_id: str = "",
        timeout: float | None = None,
    ) -> CopilotResponse:
        self.ask_calls.append(
            {
                "question": question,
                "session_id": session_id,
                "artifact_id": artifact_id,
                "incident_id": incident_id,
                "campaign_id": campaign_id,
            }
        )
        return self._response

    def copilot_update_focus(
        self,
        session_id: str,
        *,
        current_artifact_id: str = "",
        current_incident_id: str = "",
        active_campaign_id: str = "",
        recent_graph_selections: tuple[str, ...] = (),
    ) -> bool:
        self.focus_calls.append(
            {
                "session_id": session_id,
                "artifact_id": current_artifact_id,
                "incident_id": current_incident_id,
                "campaign_id": active_campaign_id,
            }
        )
        return True

    def copilot_close_session(self, session_id: str) -> bool:
        self.closed.append(session_id)
        return True


def _vm(client: BackendClient) -> CopilotViewModel:
    # These tests assert the non-streaming request/response path.
    return CopilotViewModel(client, runner_factory=SyncRunner, streaming=False)


def test_ask_produces_turn_and_answer() -> None:
    client = _FakeClient()
    vm = _vm(client)
    completed: list[ChatTurn] = []
    vm.turn_completed.connect(completed.append)

    vm.ask("why is url-1 malicious?")

    assert len(vm.turns) == 1
    turn = vm.turns[0]
    assert not turn.pending
    assert turn.answer == "Grounded answer."
    assert turn.available
    assert completed and completed[0] is turn


def test_ask_empty_emits_error_and_no_turn() -> None:
    client = _FakeClient()
    vm = _vm(client)
    errors: list[str] = []
    vm.error.connect(errors.append)

    vm.ask("   ")

    assert errors
    assert vm.turns == ()


def test_session_id_captured_and_reused() -> None:
    client = _FakeClient()
    vm = _vm(client)
    vm.ask("first")
    assert vm.session_id == "sess-1"
    vm.ask("second")
    # Second call carries the session id captured from the first.
    assert client.ask_calls[1]["session_id"] == "sess-1"


def test_focus_forwarded_on_ask() -> None:
    client = _FakeClient()
    vm = _vm(client)
    vm.set_focus(artifact_id="url-1")
    vm.ask("explain")
    assert client.ask_calls[0]["artifact_id"] == "url-1"


def test_focus_pushed_to_backend_when_session_exists() -> None:
    client = _FakeClient()
    vm = _vm(client)
    vm.ask("open a session")
    vm.set_focus(incident_id="inc-1")
    assert client.focus_calls
    assert client.focus_calls[-1]["incident_id"] == "inc-1"


def test_regenerate_replaces_last_answer() -> None:
    client = _FakeClient()
    vm = _vm(client)
    vm.ask("why?")
    assert len(vm.turns) == 1
    vm.regenerate()
    # Still one turn; the answer was regenerated in place.
    assert len(vm.turns) == 1
    assert len(client.ask_calls) == 2


def test_regenerate_without_turns_is_noop() -> None:
    client = _FakeClient()
    vm = _vm(client)
    vm.regenerate()
    assert vm.turns == ()
    assert client.ask_calls == []


def test_clear_closes_session_and_empties() -> None:
    client = _FakeClient()
    vm = _vm(client)
    cleared: list[bool] = []
    vm.cleared.connect(lambda: cleared.append(True))
    vm.ask("hi")
    vm.clear()
    assert vm.turns == ()
    assert vm.session_id == ""
    assert client.closed == ["sess-1"]
    assert cleared


def test_provider_unavailable_maps_to_error_turn() -> None:
    client = _FakeClient(_response(available=False, answer=""))
    vm = _vm(client)
    vm.ask("status?")
    turn = vm.turns[0]
    assert turn.error
    assert not turn.available
    assert "unavailable" in turn.answer.lower()


def test_transport_error_maps_to_network_message() -> None:
    response = _response(
        available=False,
        answer="",
        violations=(GroundingViolation(reason="transport_error", detail="boom"),),
    )
    client = _FakeClient(response)
    vm = _vm(client)
    vm.ask("status?")
    assert "backend" in vm.turns[0].answer.lower()


def test_busy_toggles_around_ask() -> None:
    client = _FakeClient()
    vm = _vm(client)
    states: list[bool] = []
    vm.busy_changed.connect(states.append)
    vm.ask("hi")
    # Synchronous runner: busy goes True then False.
    assert states == [True, False]


def test_citations_carried_onto_turn() -> None:
    citation = Citation(kind="threat_score", source_id="url-1", label="url-1", excerpt="sev 90%")
    client = _FakeClient(_response(citations=(citation,)))
    vm = _vm(client)
    vm.ask("why?")
    assert vm.turns[0].citations == (citation,)


def test_related_intelligence_carried_onto_turn() -> None:
    related = ContextItem(kind="ioc_intelligence", source_id="ioc-1", label="ioc-1", summary="x")
    response = CopilotResponse(answer="a", session_id="s", available=True, related=(related,))
    client = _FakeClient(response)
    vm = _vm(client)
    vm.ask("iocs?")
    assert vm.turns[0].related == (related,)

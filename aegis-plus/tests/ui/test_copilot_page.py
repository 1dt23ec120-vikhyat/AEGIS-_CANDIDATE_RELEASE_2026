"""Tests for the AI Security Copilot page, navigation, and components (M12 P2)."""

from __future__ import annotations

import pytest

from core.domain.copilot import Citation, CopilotResponse, PromptMetadata
from tests.ui._async import SyncRunner
from ui.backend import BackendClient
from ui.components.copilot.chat import (
    ChatComposer,
    CitationChip,
    MessageBubble,
    SuggestedPrompts,
    citation_kind_label,
)
from ui.components.copilot.navigation import citation_target
from ui.context import UIContext
from ui.navigation.routes import NAVIGATION, Route
from ui.pages.copilot import CopilotPage
from ui.theme import ThemeManager
from ui.viewmodels.copilot import CopilotViewModel

pytestmark = pytest.mark.ui


def _response(
    *,
    answer: str = "Grounded answer.",
    citations: tuple[Citation, ...] = (),
    available: bool = True,
) -> CopilotResponse:
    return CopilotResponse(
        answer=answer,
        citations=citations,
        session_id="sess-1",
        available=available,
        prompt_metadata=PromptMetadata(skill_id="threat_investigation", provider="fake"),
    )


class _FakeClient(BackendClient):
    def __init__(self, response: CopilotResponse | None = None) -> None:
        super().__init__("http://127.0.0.1:9")
        self._response = response or _response()
        self.ask_calls: list[dict[str, str]] = []

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
                "artifact_id": artifact_id,
                "incident_id": incident_id,
                "campaign_id": campaign_id,
            }
        )
        return self._response

    def copilot_update_focus(self, session_id: str, **kwargs: object) -> bool:
        return True

    def copilot_close_session(self, session_id: str) -> bool:
        return True


def _page(client: BackendClient | None = None, *, navigate: object = None) -> CopilotPage:
    fake = client or _FakeClient()
    context = UIContext(
        theme_manager=ThemeManager(),
        backend_client=fake,
        navigate=navigate,  # type: ignore[arg-type]
    )
    # Deterministic, non-streaming view-model with a synchronous runner.
    vm = CopilotViewModel(fake, runner_factory=SyncRunner, streaming=False)
    return CopilotPage(context, view_model=vm)


# --- registration --------------------------------------------------------


def test_copilot_route_registered_in_navigation() -> None:
    routes = {entry.route for entry in NAVIGATION}
    assert Route.COPILOT in routes


# --- page behaviour ------------------------------------------------------


def test_page_ask_appends_transcript(qapp: object) -> None:
    client = _FakeClient()
    page = _page(client)
    page._submit_prompt("why is url-1 malicious?")
    assert client.ask_calls
    assert page.view_model.turns[0].answer == "Grounded answer."


def test_suggested_prompt_submits(qapp: object) -> None:
    client = _FakeClient()
    page = _page(client)
    page._suggested.prompt_selected.emit("Summarize the current security posture")
    assert client.ask_calls[0]["question"] == "Summarize the current security posture"


def test_on_navigated_sets_artifact_focus(qapp: object) -> None:
    client = _FakeClient()
    page = _page(client)
    page.on_navigated({"focus": "url-1", "kind": "artifact", "origin": Route.URL_SCANNER})
    assert page.view_model.focus_context["artifact_id"] == "url-1"


def test_on_navigated_incident_focus(qapp: object) -> None:
    client = _FakeClient()
    page = _page(client)
    page.on_navigated({"focus": "inc-1", "kind": "incident", "origin": Route.INCIDENTS})
    assert page.view_model.focus_context["incident_id"] == "inc-1"


def test_on_navigated_autosubmits_prompt(qapp: object) -> None:
    client = _FakeClient()
    page = _page(client)
    page.on_navigated(
        {
            "focus": "url-1",
            "kind": "artifact",
            "origin": Route.URL_SCANNER,
            "prompt": "Why is this malicious?",
        }
    )
    assert client.ask_calls
    assert client.ask_calls[0]["question"] == "Why is this malicious?"
    assert client.ask_calls[0]["artifact_id"] == "url-1"


def test_clear_resets_conversation(qapp: object) -> None:
    client = _FakeClient()
    page = _page(client)
    page._submit_prompt("hi")
    assert page.view_model.turns
    page.view_model.clear()
    assert page.view_model.turns == ()


def test_citation_click_navigates(qapp: object) -> None:
    calls: list[tuple[object, object]] = []

    def navigate(route: object, payload: object = None) -> None:
        calls.append((route, payload))

    citation = Citation(kind="threat_score", source_id="url-1", label="url-1")
    client = _FakeClient(_response(citations=(citation,)))
    page = _page(client, navigate=navigate)
    page._submit_prompt("why?")
    page._open_citation(citation)
    assert calls
    route, payload = calls[0]
    assert route is Route.GRAPH_EXPLORER
    assert isinstance(payload, dict)
    assert payload["focus"] == "url-1"


def test_copy_last_uses_clipboard(qapp: object) -> None:
    from PySide6.QtWidgets import QApplication

    client = _FakeClient()
    page = _page(client)
    page._submit_prompt("why?")
    page._copy_last()
    clipboard = QApplication.clipboard()
    assert clipboard is not None
    assert clipboard.text() == "Grounded answer."


def test_regenerate_button_enabled_after_answer(qapp: object) -> None:
    client = _FakeClient()
    page = _page(client)
    assert not page._regenerate_btn.isEnabled()
    page._submit_prompt("why?")
    assert page._regenerate_btn.isEnabled()


# --- citation navigation mapping ----------------------------------------


def test_citation_target_simple() -> None:
    target = citation_target(Citation(kind="threat_score", source_id="url-1", label="url-1"))
    assert target is not None
    route, payload = target
    assert route is Route.GRAPH_EXPLORER
    assert payload["focus"] == "url-1"
    assert payload["origin"] is Route.COPILOT


def test_citation_target_pair_kind_uses_first_node() -> None:
    target = citation_target(
        Citation(kind="attack_chain", source_id="root-1->target-9", label="chain")
    )
    assert target is not None
    _, payload = target
    assert payload["focus"] == "root-1"


def test_citation_target_empty_id_returns_none() -> None:
    assert citation_target(Citation(kind="threat_score", source_id="", label="x")) is None


# --- components ----------------------------------------------------------


def test_message_bubble_role(qapp: object) -> None:
    bubble = MessageBubble("hello", role="user")
    assert bubble.property("role") == "user"
    assert bubble.text() == "hello"


def test_citation_chip_emits(qapp: object) -> None:
    citation = Citation(kind="ioc_intelligence", source_id="ioc-1", label="hash")
    chip = CitationChip(citation)
    received: list[object] = []
    chip.activated.connect(received.append)
    chip.click()
    assert received and received[0] is citation


def test_suggested_prompts_emit(qapp: object) -> None:
    from PySide6.QtWidgets import QPushButton

    prompts = SuggestedPrompts(("Alpha", "Beta"))
    received: list[str] = []
    prompts.prompt_selected.connect(received.append)
    chips = prompts.findChildren(QPushButton)
    assert len(chips) == 2
    chips[0].click()
    assert received == ["Alpha"]


def test_composer_enter_submits(qapp: object) -> None:
    composer = ChatComposer()
    received: list[str] = []
    composer.submitted.connect(received.append)
    composer.set_text("hello")
    composer._submit()
    assert received == ["hello"]


def test_citation_kind_label_known_and_unknown() -> None:
    assert citation_kind_label("threat_score") == "Threat score"
    assert citation_kind_label("something_new") == "Something New"

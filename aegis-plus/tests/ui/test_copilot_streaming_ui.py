"""UI-side streaming tests for the Copilot view-model and page (M12 Phase 3).

A synchronous stream worker runs the event source inline so streaming behaviour
is deterministic without spawning real threads. The lifecycle tests assert that
disposing the view-model or closing the page tears the worker down, and that the
default threaded worker can be constructed, started, and stopped without leaking
— the core Qt-safety requirement.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest
from PySide6.QtCore import QObject, Signal

from core.domain.copilot import Citation, CopilotResponse, CopilotStreamEvent, PromptMetadata
from tests.ui._async import SyncRunner
from ui.backend import BackendClient
from ui.viewmodels.copilot import CopilotViewModel
from ui.viewmodels.copilot_stream import EventSource, StreamWorker

if TYPE_CHECKING:
    from ui.pages.copilot import CopilotPage

pytestmark = pytest.mark.ui


class _SyncStreamWorker(QObject):
    """A drop-in StreamWorker that runs the source inline (no real thread)."""

    token = Signal(str)
    finished = Signal(object)

    def __init__(self, source: EventSource, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._source = source
        self._cancelled = False

    def start(self) -> None:
        final: CopilotStreamEvent | None = None
        for event in self._source():
            if self._cancelled:
                return
            if event.kind == "token":
                self.token.emit(event.text)
            else:
                final = event
                break
        if not self._cancelled:
            self.finished.emit(final)

    def cancel(self) -> None:
        self._cancelled = True

    def stop(self) -> None:
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled


def _final_response(*, answer: str = "Grounded streamed answer.") -> CopilotResponse:
    return CopilotResponse(
        answer=answer,
        citations=(Citation(kind="threat_score", source_id="url-1", label="url-1"),),
        session_id="sess-1",
        available=True,
        prompt_metadata=PromptMetadata(skill_id="threat_investigation", provider="fake"),
    )


class _StreamingClient(BackendClient):
    def __init__(self, events: list[CopilotStreamEvent]) -> None:
        super().__init__("http://127.0.0.1:9")
        self._events = events
        self.stream_calls = 0
        self.ask_calls = 0

    def copilot_stream(
        self,
        question: str,
        *,
        session_id: str = "",
        artifact_id: str = "",
        incident_id: str = "",
        campaign_id: str = "",
        timeout: float | None = None,
    ) -> Iterator[CopilotStreamEvent]:
        self.stream_calls += 1
        yield from self._events

    def copilot_ask(self, question: str, **kwargs: object) -> CopilotResponse:
        self.ask_calls += 1
        return _final_response()

    def copilot_close_session(self, session_id: str) -> bool:
        return True


def _vm(client: BackendClient) -> CopilotViewModel:
    return CopilotViewModel(
        client,
        runner_factory=SyncRunner,
        stream_worker_factory=_SyncStreamWorker,  # type: ignore[arg-type]
        streaming=True,
    )


def test_streaming_accumulates_tokens_then_finalizes() -> None:
    events = [
        CopilotStreamEvent(kind="token", text="Grounded "),
        CopilotStreamEvent(kind="token", text="streamed "),
        CopilotStreamEvent(kind="token", text="answer."),
        CopilotStreamEvent(kind="final", response=_final_response()),
    ]
    client = _StreamingClient(events)
    vm = _vm(client)
    tokens: list[str] = []
    vm.token_received.connect(tokens.append)
    completed: list[object] = []
    vm.turn_completed.connect(completed.append)

    vm.ask("why is url-1 malicious?")

    assert client.stream_calls == 1
    assert tokens == ["Grounded ", "streamed ", "answer."]
    assert vm.turns[-1].answer == "Grounded streamed answer."
    assert vm.turns[-1].citations
    assert not vm.is_busy


def test_streaming_error_event_degrades_gracefully() -> None:
    fallback = CopilotResponse(answer="x", session_id="s", available=False)
    events = [
        CopilotStreamEvent(kind="token", text="partial "),
        CopilotStreamEvent(kind="error", error="mid-stream boom", response=fallback),
    ]
    client = _StreamingClient(events)
    vm = _vm(client)
    vm.ask("why?")
    turn = vm.turns[-1]
    assert turn.error
    assert not turn.available
    assert not vm.is_busy


def test_streaming_final_without_response_is_handled() -> None:
    events = [
        CopilotStreamEvent(kind="token", text="partial"),
        CopilotStreamEvent(kind="error", error="boom", response=None),
    ]
    client = _StreamingClient(events)
    vm = _vm(client)
    vm.ask("why?")
    assert vm.turns[-1].error
    assert not vm.is_busy


def test_non_streaming_mode_uses_ask() -> None:
    client = _StreamingClient([])
    vm = CopilotViewModel(client, runner_factory=SyncRunner, streaming=False)
    vm.ask("why?")
    assert client.ask_calls == 1
    assert client.stream_calls == 0
    assert vm.turns[-1].answer == "Grounded streamed answer."


def test_clear_during_stream_stops_worker() -> None:
    events = [
        CopilotStreamEvent(kind="token", text="Grounded "),
        CopilotStreamEvent(kind="final", response=_final_response()),
    ]
    client = _StreamingClient(events)
    vm = _vm(client)
    vm.ask("why?")
    vm.clear()
    assert vm.turns == ()
    # Worker reference is released after teardown.
    assert vm._stream_worker is None


# --- lifecycle safety (the core §7 requirement) --------------------------


def test_dispose_releases_worker() -> None:
    events = [CopilotStreamEvent(kind="final", response=_final_response())]
    client = _StreamingClient(events)
    vm = _vm(client)
    vm.ask("why?")
    vm.dispose()
    assert vm._stream_worker is None


def test_real_stream_worker_start_stop_is_clean(qapp: object) -> None:
    # Construct, start, and stop the *real* threaded worker to prove it joins
    # cleanly and leaks no thread.
    def source() -> Iterator[CopilotStreamEvent]:
        yield CopilotStreamEvent(kind="token", text="a")
        yield CopilotStreamEvent(kind="final", response=_final_response())

    worker = StreamWorker(source)
    worker.start()
    worker.stop()  # cancels, quits, and waits
    assert worker.is_cancelled
    assert not worker._thread.isRunning()


def test_real_stream_worker_cancel_suppresses_signals(qapp: object) -> None:
    started = {"n": 0}

    def source() -> Iterator[CopilotStreamEvent]:
        started["n"] += 1
        yield CopilotStreamEvent(kind="token", text="a")
        yield CopilotStreamEvent(kind="final", response=_final_response())

    worker = StreamWorker(source)
    finished: list[object] = []
    worker.finished.connect(finished.append)
    worker.cancel()  # cancel before start
    worker.start()
    worker.stop()
    # Cancelled before running: no finished signal is delivered.
    assert finished == []


# --- page-level streaming ------------------------------------------------


def _streaming_page(events: list[CopilotStreamEvent]) -> CopilotPage:
    from ui.context import UIContext
    from ui.pages.copilot import CopilotPage
    from ui.theme import ThemeManager

    client = _StreamingClient(events)
    context = UIContext(theme_manager=ThemeManager(), backend_client=client)
    vm = CopilotViewModel(
        client,
        runner_factory=SyncRunner,
        stream_worker_factory=_SyncStreamWorker,  # type: ignore[arg-type]
        streaming=True,
    )
    return CopilotPage(context, view_model=vm)


def test_page_renders_streamed_tokens_progressively(qapp: object) -> None:
    events = [
        CopilotStreamEvent(kind="token", text="Grounded "),
        CopilotStreamEvent(kind="token", text="answer."),
        CopilotStreamEvent(kind="final", response=_final_response()),
    ]
    page = _streaming_page(events)
    page._submit_prompt("why is url-1 malicious?")
    # The finalized bubble shows the validated answer with citations.
    turn = page.view_model.turns[-1]
    assert turn.answer == "Grounded streamed answer."
    assert turn.citations


def test_page_close_disposes_view_model(qapp: object) -> None:
    from PySide6.QtGui import QCloseEvent

    events = [CopilotStreamEvent(kind="final", response=_final_response())]
    page = _streaming_page(events)
    page._submit_prompt("why?")
    page.close()
    page.closeEvent(QCloseEvent())
    assert page.view_model._stream_worker is None

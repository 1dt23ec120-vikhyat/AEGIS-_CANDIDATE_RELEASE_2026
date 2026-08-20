"""AI Security Copilot view-model (M12 Phase 3).

The MVVM view-model for the Copilot page. It owns the presentation state of the
active conversation, performs all backend access through :class:`BackendClient`
on worker threads, and exposes everything to the page via Qt signals. It holds no
intelligence logic and never touches services or the domain pipeline directly.

Streaming: when enabled, the view-model consumes the backend stream through a
lifecycle-safe :class:`StreamWorker`, emitting progressive tokens and finalizing
with the grounding-validated response. Streaming failures fall back to the
non-streaming ``/api/copilot/ask`` path automatically. The worker is explicitly
stopped on clear, on a new request, and on view-model disposal, so no worker
survives the page or the ``QApplication``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from PySide6.QtCore import QObject, Signal

from core.domain.copilot import (
    Citation,
    ContextItem,
    CopilotResponse,
    CopilotStreamEvent,
    PromptMetadata,
)
from ui.backend import AsyncRunner, BackendClient
from ui.viewmodels.base import ViewModel
from ui.viewmodels.copilot_stream import EventSource, StreamWorker

RunnerFactory = Callable[[QObject], AsyncRunner]
StreamWorkerFactory = Callable[[EventSource, QObject], StreamWorker]

# Analyst-friendly messages — never expose stack traces or transport internals.
_MSG_UNAVAILABLE = (
    "The Copilot is unavailable right now. The language model provider is not "
    "configured or could not be reached. The platform's deterministic "
    "intelligence remains fully available in the dashboards."
)
_MSG_NETWORK = (
    "The Copilot could not reach the backend. Check that the local service is "
    "running and try again."
)
_MSG_EMPTY = "Please enter a question for the Copilot."


@dataclass(slots=True)
class ChatTurn:
    """One presentation-level conversation turn."""

    question: str
    answer: str = ""
    citations: tuple[Citation, ...] = ()
    related: tuple[ContextItem, ...] = ()
    prompt_metadata: PromptMetadata = field(default_factory=PromptMetadata)
    latency_ms: float = 0.0
    available: bool = True
    grounding_score: float = 1.0
    pending: bool = True
    error: bool = False


@dataclass(frozen=True, slots=True)
class _AskOutcome:
    response: CopilotResponse
    elapsed_ms: float
    regenerated: bool


class CopilotViewModel(ViewModel):
    """Presentation state and backend orchestration for the Copilot."""

    turn_started = Signal(object)  # ChatTurn (pending, user question shown)
    turn_completed = Signal(object)  # ChatTurn (answer filled in)
    token_received = Signal(str)  # incremental token text during streaming
    busy_changed = Signal(bool)
    error = Signal(str)
    cleared = Signal()
    focus_changed = Signal(object)  # dict describing the active focus context

    def __init__(
        self,
        client: BackendClient,
        *,
        runner_factory: RunnerFactory = AsyncRunner,
        stream_worker_factory: StreamWorkerFactory = StreamWorker,
        streaming: bool = True,
    ) -> None:
        """Initialize the view-model.

        Args:
            client: Backend gateway for Copilot requests.
            runner_factory: Builds the workers that run backend calls off the UI
                thread. Defaults to the threaded :class:`AsyncRunner`; tests can
                inject a synchronous runner for deterministic execution.
            stream_worker_factory: Builds the streaming worker. Defaults to the
                threaded :class:`StreamWorker`; tests can inject a synchronous
                worker for deterministic execution.
            streaming: Whether to use the streaming path when available. When
                ``False``, the non-streaming path is always used.
        """
        super().__init__()
        self._client = client
        self._runner_factory = runner_factory
        self._runner = runner_factory(self)
        self._runner.finished.connect(self._on_answer)
        self._stream_worker_factory = stream_worker_factory
        self._streaming_enabled = streaming

        self._turns: list[ChatTurn] = []
        self._session_id = ""
        self._busy = False
        self._focus_artifact = ""
        self._focus_incident = ""
        self._focus_campaign = ""
        self._stream_worker: StreamWorker | None = None
        self._stream_buffer = ""

    # --- state -----------------------------------------------------------

    @property
    def turns(self) -> tuple[ChatTurn, ...]:
        """The conversation turns for the active session."""
        return tuple(self._turns)

    @property
    def session_id(self) -> str:
        """The active in-memory session id (assigned by the backend)."""
        return self._session_id

    @property
    def is_busy(self) -> bool:
        """Whether a request is in flight."""
        return self._busy

    @property
    def focus_context(self) -> dict[str, str]:
        """The current focus (artifact/incident/campaign) sent with each ask."""
        return {
            "artifact_id": self._focus_artifact,
            "incident_id": self._focus_incident,
            "campaign_id": self._focus_campaign,
        }

    # --- focus (from launch points) --------------------------------------

    def set_focus(
        self, *, artifact_id: str = "", incident_id: str = "", campaign_id: str = ""
    ) -> None:
        """Set the investigation focus attached to subsequent questions.

        The backend performs all context collection; the view-model only forwards
        the focus ids it was launched with. When a session already exists, the
        focus is also pushed to the backend so it informs ranking.
        """
        self._focus_artifact = artifact_id
        self._focus_incident = incident_id
        self._focus_campaign = campaign_id
        self.focus_changed.emit(self.focus_context)
        if self._session_id:
            session = self._session_id
            self._client.copilot_update_focus(
                session,
                current_artifact_id=artifact_id,
                current_incident_id=incident_id,
                active_campaign_id=campaign_id,
            )

    # --- asking ----------------------------------------------------------

    def ask(self, question: str) -> None:
        """Submit a question to the Copilot."""
        text = question.strip()
        if not text:
            self.error.emit(_MSG_EMPTY)
            return
        if self._busy:
            return
        turn = ChatTurn(question=text)
        self._turns.append(turn)
        self.turn_started.emit(turn)
        self._dispatch(turn, regenerated=False)

    def regenerate(self) -> None:
        """Re-ask the most recent question, replacing its answer in place."""
        if self._busy or not self._turns:
            return
        last = self._turns[-1]
        last.answer = ""
        last.citations = ()
        last.related = ()
        last.pending = True
        last.error = False
        self.turn_started.emit(last)
        self._dispatch(last, regenerated=True)

    def clear(self) -> None:
        """Clear the active conversation and close the backend session."""
        self._stop_stream()
        if self._session_id:
            session = self._session_id
            self._client.copilot_close_session(session)
        self._turns.clear()
        self._session_id = ""
        self._set_busy(False)
        self.cleared.emit()

    def dispose(self) -> None:
        """Release worker threads. Call when the page is destroyed."""
        self._stop_stream()

    # --- stream lifecycle ------------------------------------------------

    def _stop_stream(self) -> None:
        """Cancel and join any in-flight stream worker (idempotent)."""
        worker = self._stream_worker
        if worker is not None:
            worker.stop()
            self._teardown_stream()

    def _teardown_stream(self) -> None:
        worker = self._stream_worker
        if worker is not None:
            worker.deleteLater()
            self._stream_worker = None

    # --- internals -------------------------------------------------------

    def _dispatch(self, turn: ChatTurn, *, regenerated: bool) -> None:
        self._set_busy(True)
        if self._streaming_enabled:
            self._dispatch_streaming(turn)
        else:
            self._dispatch_blocking(turn, regenerated=regenerated)

    def _dispatch_blocking(self, turn: ChatTurn, *, regenerated: bool) -> None:
        question = turn.question
        session = self._session_id
        artifact = self._focus_artifact
        incident = self._focus_incident
        campaign = self._focus_campaign

        def call() -> _AskOutcome:
            start = time.perf_counter()
            response = self._client.copilot_ask(
                question,
                session_id=session,
                artifact_id=artifact,
                incident_id=incident,
                campaign_id=campaign,
            )
            elapsed = (time.perf_counter() - start) * 1000
            return _AskOutcome(response=response, elapsed_ms=elapsed, regenerated=regenerated)

        self._runner.run(call)

    def _dispatch_streaming(self, turn: ChatTurn) -> None:
        self._stop_stream()
        self._stream_buffer = ""
        question = turn.question
        session = self._session_id
        artifact = self._focus_artifact
        incident = self._focus_incident
        campaign = self._focus_campaign

        def source() -> Iterator[CopilotStreamEvent]:
            return self._client.copilot_stream(
                question,
                session_id=session,
                artifact_id=artifact,
                incident_id=incident,
                campaign_id=campaign,
            )

        worker = self._stream_worker_factory(source, self)
        worker.token.connect(self._on_token)
        worker.finished.connect(self._on_stream_finished)
        self._stream_worker = worker
        worker.start()

    def _on_token(self, text: str) -> None:
        self._stream_buffer += text
        self.token_received.emit(text)

    def _on_stream_finished(self, event: object) -> None:
        self._teardown_stream()
        if not isinstance(event, CopilotStreamEvent) or not self._turns:
            self._set_busy(False)
            return
        if event.response is not None:
            self._apply_response(event.response, elapsed_ms=0.0)
        else:
            # Terminal event without a response payload — fall back gracefully.
            turn = self._turns[-1]
            turn.pending = False
            turn.error = True
            turn.available = False
            turn.answer = _MSG_UNAVAILABLE
            self.turn_completed.emit(turn)
        self._set_busy(False)

    def _on_answer(self, outcome: object) -> None:
        if not isinstance(outcome, _AskOutcome) or not self._turns:
            self._set_busy(False)
            return
        self._apply_response(outcome.response, elapsed_ms=outcome.elapsed_ms)
        self._set_busy(False)

    def _apply_response(self, response: CopilotResponse, *, elapsed_ms: float) -> None:
        turn = self._turns[-1]
        if response.session_id:
            self._session_id = response.session_id

        turn.pending = False
        turn.available = response.available
        turn.grounding_score = response.grounding_score
        turn.prompt_metadata = response.prompt_metadata
        turn.latency_ms = response.latency_ms or elapsed_ms

        if not response.available:
            turn.error = True
            turn.answer = self._degraded_message(response)
            turn.citations = ()
            turn.related = ()
        else:
            turn.error = False
            turn.answer = response.answer
            turn.citations = response.citations
            turn.related = response.related

        self.turn_completed.emit(turn)

    def _degraded_message(self, response: CopilotResponse) -> str:
        for violation in response.grounding_violations:
            if violation.reason == "transport_error":
                return _MSG_NETWORK
        return _MSG_UNAVAILABLE

    def _set_busy(self, busy: bool) -> None:
        if busy == self._busy:
            return
        self._busy = busy
        self.busy_changed.emit(busy)

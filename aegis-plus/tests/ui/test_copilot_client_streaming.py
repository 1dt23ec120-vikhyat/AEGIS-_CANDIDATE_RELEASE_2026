"""BackendClient streaming tests (M12 Phase 3).

Exercises the SSE line parser and the transport-error fallback without a live
server. The client must yield typed events on success and a single graceful
``error`` event (never raise) when the stream cannot be reached.
"""

from __future__ import annotations

import json

import httpx
import pytest

from core.domain.copilot import CopilotStreamEvent
from ui.backend import BackendClient
from ui.backend.client import _parse_stream_line

pytestmark = pytest.mark.ui


def test_parse_stream_line_token() -> None:
    line = 'data: {"kind": "token", "text": "hello"}'
    event = _parse_stream_line(line)
    assert isinstance(event, CopilotStreamEvent)
    assert event.kind == "token"
    assert event.text == "hello"


def test_parse_stream_line_final_with_response() -> None:
    payload = {
        "kind": "final",
        "response": {
            "answer": "Grounded.",
            "citations": [],
            "session_id": "s-1",
            "available": True,
        },
    }
    event = _parse_stream_line(f"data: {json.dumps(payload)}")
    assert event is not None
    assert event.kind == "final"
    assert event.response is not None
    assert event.response.answer == "Grounded."
    assert event.response.session_id == "s-1"


def test_parse_stream_line_ignores_non_data() -> None:
    assert _parse_stream_line("event: ping") is None
    assert _parse_stream_line("") is None
    assert _parse_stream_line("data: ") is None


def test_parse_stream_line_bad_json() -> None:
    assert _parse_stream_line("data: {not json}") is None


def test_copilot_stream_transport_error_yields_graceful_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = BackendClient("http://127.0.0.1:9")

    def _boom(*args: object, **kwargs: object) -> object:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "stream", _boom)
    events = list(client.copilot_stream("why?"))
    assert len(events) == 1
    assert events[0].kind == "error"
    assert events[0].response is not None
    assert events[0].response.available is False

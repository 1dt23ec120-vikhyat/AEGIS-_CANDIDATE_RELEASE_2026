"""AI Security Copilot API (M12 Phase 1).

Read-only endpoints that expose the Copilot's grounded reasoning over the
platform's deterministic intelligence. The Copilot never mutates state, so these
endpoints add no persistence: ``/ask`` answers a question, the focus endpoint
records what the analyst is looking at (in memory), and the session endpoints
inspect and close in-memory conversations.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from core.domain.copilot import CopilotQuery, CopilotResponse, CopilotStreamEvent
from core.domain.copilot_session import FocusState
from services.copilot import CopilotOrchestrator, SessionManager


class AskRequest(BaseModel):
    """A question for the Copilot."""

    question: str = Field(min_length=1, max_length=4000)
    session_id: str = Field(default="", max_length=128)
    artifact_id: str = Field(default="", max_length=256)
    incident_id: str = Field(default="", max_length=256)
    campaign_id: str = Field(default="", max_length=256)


class FocusRequest(BaseModel):
    """An update to the analyst's current focus."""

    current_artifact_id: str = Field(default="", max_length=256)
    current_incident_id: str = Field(default="", max_length=256)
    active_campaign_id: str = Field(default="", max_length=256)
    recent_graph_selections: list[str] = Field(default_factory=list)


class CitationModel(BaseModel):
    """A resolved citation to a platform source."""

    kind: str
    source_id: str
    label: str
    excerpt: str


class RelatedModel(BaseModel):
    """A related intelligence reference consulted but not directly cited."""

    kind: str
    source_id: str
    label: str
    summary: str


class ViolationModel(BaseModel):
    """A grounding violation."""

    reason: str
    detail: str


class PromptMetadataModel(BaseModel):
    """Prompt provenance carried on every response."""

    prompt_id: str
    prompt_version: str
    skill_id: str
    intent: str
    model_id: str
    provider: str
    temperature: float
    timestamp: str
    context_item_count: int
    prompt_token_estimate: int


class AskResponse(BaseModel):
    """The Copilot's grounded answer."""

    answer: str
    citations: list[CitationModel]
    related: list[RelatedModel]
    context_summary: list[str]
    grounding_score: float
    grounding_violations: list[ViolationModel]
    prompt_metadata: PromptMetadataModel
    session_id: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    available: bool


class TurnModel(BaseModel):
    """One in-memory conversation turn."""

    question: str
    answer: str
    intent: str
    timestamp: str


class SessionModel(BaseModel):
    """An in-memory conversation session."""

    session_id: str
    turns: list[TurnModel]
    created_at: str
    updated_at: str


def _response_model(response: CopilotResponse) -> AskResponse:
    meta = response.prompt_metadata
    return AskResponse(
        answer=response.answer,
        citations=[
            CitationModel(kind=c.kind, source_id=c.source_id, label=c.label, excerpt=c.excerpt)
            for c in response.citations
        ],
        related=[
            RelatedModel(kind=r.kind, source_id=r.source_id, label=r.label, summary=r.summary)
            for r in response.related
        ],
        context_summary=list(response.context_summary),
        grounding_score=response.grounding_score,
        grounding_violations=[
            ViolationModel(reason=v.reason, detail=v.detail) for v in response.grounding_violations
        ],
        prompt_metadata=PromptMetadataModel(
            prompt_id=meta.prompt_id,
            prompt_version=meta.prompt_version,
            skill_id=meta.skill_id,
            intent=meta.intent,
            model_id=meta.model_id,
            provider=meta.provider,
            temperature=meta.temperature,
            timestamp=meta.timestamp,
            context_item_count=meta.context_item_count,
            prompt_token_estimate=meta.prompt_token_estimate,
        ),
        session_id=response.session_id,
        prompt_tokens=response.prompt_tokens,
        completion_tokens=response.completion_tokens,
        latency_ms=response.latency_ms,
        available=response.available,
    )


def _sse(event: CopilotStreamEvent) -> str:
    """Serialize a stream event as one SSE ``data:`` frame of JSON."""
    payload: dict[str, object] = {"kind": event.kind}
    if event.kind == "token":
        payload["text"] = event.text
    elif event.kind == "error":
        payload["error"] = event.error
    if event.response is not None:
        payload["response"] = _response_model(event.response).model_dump()
    return f"data: {json.dumps(payload)}\n\n"


def _orchestrator(request: Request) -> CopilotOrchestrator:
    service: CopilotOrchestrator = request.app.state.copilot_orchestrator
    return service


def _sessions(request: Request) -> SessionManager:
    service: SessionManager = request.app.state.copilot_sessions
    return service


def build_router() -> APIRouter:
    """Build the AI Security Copilot API router."""
    router = APIRouter(prefix="/api/copilot", tags=["copilot"])

    @router.post("/ask", response_model=AskResponse)
    def ask(request: Request, payload: AskRequest) -> AskResponse:
        query = CopilotQuery(
            question=payload.question,
            session_id=payload.session_id,
            artifact_id=payload.artifact_id,
            incident_id=payload.incident_id,
            campaign_id=payload.campaign_id,
        )
        return _response_model(_orchestrator(request).ask(query))

    @router.post("/ask/stream")
    def ask_stream(request: Request, payload: AskRequest) -> StreamingResponse:
        query = CopilotQuery(
            question=payload.question,
            session_id=payload.session_id,
            artifact_id=payload.artifact_id,
            incident_id=payload.incident_id,
            campaign_id=payload.campaign_id,
        )
        orchestrator = _orchestrator(request)

        def event_stream() -> Iterator[str]:
            for event in orchestrator.stream_ask(query):
                yield _sse(event)

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    @router.post("/session/{session_id}/focus", status_code=status.HTTP_204_NO_CONTENT)
    def update_focus(request: Request, session_id: str, payload: FocusRequest) -> None:
        _orchestrator(request).update_focus(
            session_id,
            FocusState(
                current_artifact_id=payload.current_artifact_id,
                current_incident_id=payload.current_incident_id,
                active_campaign_id=payload.active_campaign_id,
                recent_graph_selections=tuple(payload.recent_graph_selections),
            ),
        )

    @router.get("/session/{session_id}", response_model=SessionModel)
    def get_session(request: Request, session_id: str) -> SessionModel:
        session = _sessions(request).get(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")
        return SessionModel(
            session_id=session.session_id,
            turns=[
                TurnModel(
                    question=t.question,
                    answer=t.answer,
                    intent=t.intent,
                    timestamp=t.timestamp,
                )
                for t in session.turns
            ],
            created_at=session.created_at,
            updated_at=session.updated_at,
        )

    @router.delete("/session/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
    def close_session(request: Request, session_id: str) -> None:
        if not _sessions(request).close(session_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")

    return router

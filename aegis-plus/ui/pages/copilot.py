"""AI Security Copilot page (M12 Phase 2).

The analyst's conversational interface to the intelligence platform. The page is
a pure presentation surface: it renders the conversation held by
:class:`CopilotViewModel`, forwards user input to it, and reuses the existing
routing framework to open cited sources. It contains no intelligence logic and
reaches the backend only through the view-model's :class:`BackendClient`.

Launched standalone from the sidebar, or from an investigation/Explorer/dashboard
via the router payload ``{focus, kind, origin, prompt}`` — in which case the page
sets the focus context (the backend collects the matching intelligence) and may
auto-submit a suggested prompt.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core.domain.copilot import Citation
from ui.components.buttons import Button
from ui.components.copilot.chat import (
    ChatComposer,
    CitationsRow,
    MessageBubble,
    MetadataRow,
    SuggestedPrompts,
    TypingIndicator,
)
from ui.components.copilot.navigation import citation_target
from ui.components.empty_state import EmptyState
from ui.components.text import label
from ui.context import UIContext
from ui.navigation.routes import Route
from ui.pages.base_page import BasePage
from ui.viewmodels.copilot import ChatTurn, CopilotViewModel

# Default quick actions when no specific focus is set.
_DEFAULT_PROMPTS: tuple[str, ...] = (
    "Summarize the current security posture",
    "What should I investigate next?",
    "Show the highest-priority threats",
)

# Focus-specific quick actions keyed by the launch "kind".
_FOCUS_PROMPTS: dict[str, tuple[str, ...]] = {
    "artifact": (
        "Why is this malicious?",
        "Explain this threat",
        "Show related IOCs",
        "What should I investigate next?",
    ),
    "incident": (
        "Summarize this incident",
        "Explain the attack chain",
        "What is the root cause?",
    ),
    "campaign": (
        "Explain this campaign",
        "Show related campaigns",
        "Which artifacts belong to it?",
    ),
    "global": _DEFAULT_PROMPTS,
}

_ORIGIN_PROMPTS: dict[Route, str] = {
    Route.URL_SCANNER: "artifact",
    Route.EMAIL_SCANNER: "artifact",
    Route.FILE_SCANNER: "artifact",
    Route.INCIDENTS: "incident",
    Route.GRAPH_EXPLORER: "artifact",
    Route.DASHBOARD: "global",
}


class CopilotPage(BasePage):
    """The AI Security Copilot conversational workspace."""

    def __init__(
        self,
        context: UIContext,
        *,
        parent: QWidget | None = None,
        view_model: CopilotViewModel | None = None,
    ) -> None:
        """Build the Copilot page.

        Args:
            context: Shared UI dependencies (theme, backend client, navigation).
            parent: Optional Qt parent.
            view_model: Optional pre-built view-model (tests inject a deterministic
                one); by default the page builds its own.
        """
        super().__init__(
            "AI Security Copilot",
            "Ask about any threat, IOC, incident, or campaign — answers are grounded "
            "in the platform's deterministic intelligence.",
            parent=parent,
        )
        self._context = context
        self._vm = (
            view_model if view_model is not None else CopilotViewModel(context.backend_client)
        )
        self._dev_mode = False
        self._typing: TypingIndicator | None = None
        self._origin: Route | None = None
        self._bubbles: dict[int, tuple[MessageBubble, QVBoxLayout]] = {}
        self._streaming_text = ""

        self._clear_btn = Button("Clear conversation", variant="ghost")
        self._clear_btn.clicked.connect(self._vm.clear)
        self.header.add_action(self._clear_btn)

        self._suggested = SuggestedPrompts(_DEFAULT_PROMPTS)
        self._suggested.prompt_selected.connect(self._submit_prompt)
        self.add(self._suggested)

        self._transcript = QVBoxLayout()
        self._transcript.setSpacing(12)
        self._transcript.setContentsMargins(0, 0, 0, 0)
        transcript_host = QWidget()
        transcript_host.setLayout(self._transcript)

        self._empty = EmptyState(
            icon_name="copilot",
            title="Start a conversation",
            subtitle=(
                "Ask a question or pick a suggestion above. The Copilot explains the "
                "platform's findings and cites its sources."
            ),
        )
        self._transcript.addWidget(self._empty)
        self._transcript.addStretch(1)

        self._scroll = QScrollArea()
        self._scroll.setObjectName("ChatScroll")
        self._scroll.setWidgetResizable(True)
        self._scroll.setWidget(transcript_host)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.add(self._scroll)

        self._composer = ChatComposer()
        self._composer.submitted.connect(self._submit_prompt)
        self.add(self._composer)

        self._build_action_row()

        self._connect_vm()

        # Guarantee worker cleanup at application shutdown, independent of page
        # lifecycle, so no streaming worker survives the QApplication.
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self._vm.dispose)

    # --- view-model wiring ----------------------------------------------

    def _build_action_row(self) -> None:
        self._action_row = QHBoxLayout()
        self._action_row.setContentsMargins(0, 0, 0, 0)
        self._regenerate_btn = Button("Regenerate", variant="secondary")
        self._regenerate_btn.clicked.connect(self._vm.regenerate)
        self._regenerate_btn.setEnabled(False)
        self._copy_btn = Button("Copy response", variant="ghost")
        self._copy_btn.clicked.connect(self._copy_last)
        self._copy_btn.setEnabled(False)
        self._dev_btn = Button("Developer mode", variant="ghost")
        self._dev_btn.setCheckable(True)
        self._dev_btn.toggled.connect(self._toggle_dev)
        self._action_row.addWidget(self._regenerate_btn)
        self._action_row.addWidget(self._copy_btn)
        self._action_row.addStretch(1)
        self._action_row.addWidget(self._dev_btn)
        self.add_layout(self._action_row)

    def _connect_vm(self) -> None:
        self._vm.turn_started.connect(self._on_turn_started)
        self._vm.turn_completed.connect(self._on_turn_completed)
        self._vm.token_received.connect(self._on_token)
        self._vm.busy_changed.connect(self._on_busy)
        self._vm.error.connect(self._on_error)
        self._vm.cleared.connect(self._on_cleared)

    @property
    def view_model(self) -> CopilotViewModel:
        """The page's view-model (exposed for tests)."""
        return self._vm

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt override
        """Release the view-model's worker threads when the page closes."""
        self._vm.dispose()
        super().closeEvent(event)

    # --- navigation integration -----------------------------------------

    def on_navigated(self, payload: object) -> None:
        """Accept launch context from an investigation/Explorer/dashboard.

        Payload keys: ``focus`` (entity id), ``kind`` (artifact/incident/campaign/
        global), ``origin`` (source :class:`Route`), and optional ``prompt`` to
        auto-submit.
        """
        if not isinstance(payload, dict):
            return
        origin = payload.get("origin")
        self._origin = origin if isinstance(origin, Route) else None
        kind = payload.get("kind")
        if not isinstance(kind, str):
            kind = _ORIGIN_PROMPTS.get(self._origin, "global") if self._origin else "global"
        focus = payload.get("focus")
        focus_id = focus if isinstance(focus, str) else ""

        if kind == "incident":
            self._vm.set_focus(incident_id=focus_id)
        elif kind == "campaign":
            self._vm.set_focus(campaign_id=focus_id)
        elif kind == "artifact":
            self._vm.set_focus(artifact_id=focus_id)
        else:
            self._vm.set_focus()

        self._suggested.set_prompts(_FOCUS_PROMPTS.get(kind, _DEFAULT_PROMPTS))

        prompt = payload.get("prompt")
        if isinstance(prompt, str) and prompt.strip():
            self._submit_prompt(prompt)
        else:
            self._composer.focus_input()

    # --- user actions ----------------------------------------------------

    def _submit_prompt(self, text: str) -> None:
        self._vm.ask(text)

    def _copy_last(self) -> None:
        turns = self._vm.turns
        if not turns or not turns[-1].answer:
            return
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(turns[-1].answer)

    def _toggle_dev(self, enabled: bool) -> None:
        self._dev_mode = enabled

    # --- view-model reactions -------------------------------------------

    def _on_turn_started(self, turn: object) -> None:
        if not isinstance(turn, ChatTurn):
            return
        self._empty.setVisible(False)
        index = self._vm.turns.index(turn) if turn in self._vm.turns else len(self._bubbles)

        # Regeneration reuses an existing assistant bubble.
        if index in self._bubbles:
            _, answer_layout = self._bubbles[index]
            self._reset_answer_container(answer_layout)
        else:
            self._append_user_bubble(turn.question)
            self._append_answer_container(index)
        self._streaming_text = ""
        self._show_typing()

    def _on_token(self, text: object) -> None:
        if not isinstance(text, str):
            return
        # First token: replace the typing indicator with a live answer bubble.
        if not self._streaming_text:
            self._hide_typing()
        self._streaming_text += text
        index = len(self._bubbles) - 1
        container = self._bubbles.get(index)
        if container is None:
            return
        bubble, _ = container
        bubble.set_text(self._streaming_text)
        self._auto_scroll()

    def _on_turn_completed(self, turn: object) -> None:
        if not isinstance(turn, ChatTurn):
            return
        self._hide_typing()
        index = self._vm.turns.index(turn) if turn in self._vm.turns else len(self._bubbles) - 1
        container = self._bubbles.get(index)
        if container is None:
            self._append_answer_container(index)
            container = self._bubbles.get(index)
        if container is None:
            return
        bubble, host_layout = container
        role = "error" if turn.error else "assistant"
        bubble.setProperty("role", role)
        bubble.set_text(turn.answer or "No answer was returned.")
        self._restyle(bubble)

        if turn.available and turn.citations:
            row = CitationsRow(turn.citations)
            row.citation_clicked.connect(self._open_citation)
            host_layout.addWidget(row)
        if turn.available and not turn.error:
            host_layout.addWidget(MetadataRow(self._metadata_text(turn)))

        self._regenerate_btn.setEnabled(True)
        self._copy_btn.setEnabled(bool(turn.answer) and not turn.error)
        self._auto_scroll()

    def _on_busy(self, busy: bool) -> None:
        self._composer.set_enabled_state(not busy)
        self._regenerate_btn.setEnabled(not busy and bool(self._vm.turns))

    def _on_error(self, message: str) -> None:
        self._append_system_note(message)

    def _on_cleared(self) -> None:
        while self._transcript.count():
            item = self._transcript.takeAt(0)
            if item is None:
                break
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._bubbles.clear()
        self._typing = None
        self._transcript.addWidget(self._empty)
        self._empty.setVisible(True)
        self._transcript.addStretch(1)
        self._regenerate_btn.setEnabled(False)
        self._copy_btn.setEnabled(False)

    # --- transcript construction ----------------------------------------

    def _insert_index(self) -> int:
        # Insert before the trailing stretch.
        return max(0, self._transcript.count() - 1)

    def _append_user_bubble(self, text: str) -> None:
        row = self._aligned_row(MessageBubble(text, role="user"), right=True)
        self._transcript.insertWidget(self._insert_index(), row)

    def _append_answer_container(self, index: int) -> None:
        bubble = MessageBubble("", role="assistant")
        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(0, 0, 0, 0)
        host_layout.setSpacing(4)
        host_layout.addWidget(bubble)
        row = self._aligned_row(host, right=False)
        self._transcript.insertWidget(self._insert_index(), row)
        self._bubbles[index] = (bubble, host_layout)

    def _reset_answer_container(self, layout: QVBoxLayout) -> None:
        # Keep the first widget (the bubble); drop citations/metadata rows.
        while layout.count() > 1:
            item = layout.takeAt(1)
            if item is None:
                break
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _aligned_row(self, widget: QWidget, *, right: bool) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        if right:
            layout.addStretch(1)
            layout.addWidget(widget)
        else:
            layout.addWidget(widget)
            layout.addStretch(1)
        return row

    def _append_system_note(self, text: str) -> None:
        note = label(text, role="muted")
        note.setWordWrap(True)
        self._transcript.insertWidget(self._insert_index(), note)
        self._auto_scroll()

    def _show_typing(self) -> None:
        if self._typing is not None:
            return
        self._typing = TypingIndicator()
        row = self._aligned_row(self._typing, right=False)
        self._typing.setParent(row)
        self._transcript.insertWidget(self._insert_index(), row)
        self._auto_scroll()

    def _hide_typing(self) -> None:
        if self._typing is None:
            return
        parent = self._typing.parentWidget()
        if parent is not None:
            parent.deleteLater()
        self._typing = None

    # --- helpers ---------------------------------------------------------

    def _metadata_text(self, turn: ChatTurn) -> str:
        meta = turn.prompt_metadata
        parts: list[str] = []
        if meta.skill_id:
            parts.append(f"skill: {meta.skill_id}")
        if turn.latency_ms:
            parts.append(f"{turn.latency_ms:.0f} ms")
        if meta.provider:
            parts.append(f"provider: {meta.provider}")
        parts.append(f"grounding: {turn.grounding_score * 100:.0f}%")
        if self._dev_mode:
            if meta.model_id:
                parts.append(f"model: {meta.model_id}")
            if meta.prompt_id:
                parts.append(f"prompt: {meta.prompt_id} v{meta.prompt_version}")
        return "   ·   ".join(parts)

    def _open_citation(self, citation: object) -> None:
        if not isinstance(citation, Citation):
            return
        target = citation_target(citation)
        if target is None:
            return
        route, payload = target
        self._context.go_to(route, payload)

    def _restyle(self, widget: QWidget) -> None:
        style = widget.style()
        style.unpolish(widget)
        style.polish(widget)

    def _auto_scroll(self) -> None:
        # Scroll immediately, then once more after the event loop has processed
        # the newly inserted widgets. The follow-up timer is parented to this
        # page so it is torn down with the page rather than outliving it.
        self._scroll_to_bottom()
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(self._scroll_to_bottom)
        timer.timeout.connect(timer.deleteLater)
        timer.start(0)

    def _scroll_to_bottom(self) -> None:
        bar = self._scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

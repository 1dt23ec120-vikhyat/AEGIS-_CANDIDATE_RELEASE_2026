"""AI Security Copilot chat components (M12 Phase 2).

Presentation-only widgets for the Copilot conversation: message bubbles, clickable
citation chips, a typing indicator, suggested-prompt quick actions, and the
multiline composer. All styling is driven by object names resolved in the shared
stylesheet, so no widget hardcodes colours.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.domain.copilot import Citation
from ui.components.text import label

_CITATION_LABELS: dict[str, str] = {
    "threat_score": "Threat score",
    "ioc_intelligence": "IOC",
    "campaign_intelligence": "Campaign",
    "attack_chain": "Attack chain",
    "root_cause": "Root cause",
    "blast_radius": "Blast radius",
    "neighbourhood": "Neighbourhood",
    "central_node": "Central node",
    "recommendation": "Recommendation",
}


def citation_kind_label(kind: str) -> str:
    """Human-readable label for a citation kind."""
    return _CITATION_LABELS.get(kind, kind.replace("_", " ").title())


class MessageBubble(QFrame):
    """A single chat message bubble (user or assistant)."""

    def __init__(
        self, text: str, *, role: str = "assistant", parent: QWidget | None = None
    ) -> None:
        """Initialize the bubble.

        Args:
            text: Message text.
            role: ``"user"``, ``"assistant"``, or ``"error"``.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self.setObjectName("ChatBubble")
        self.setProperty("role", role)
        column = QVBoxLayout(self)
        column.setContentsMargins(14, 10, 14, 10)
        column.setSpacing(6)
        self._body = QLabel(text)
        self._body.setWordWrap(True)
        self._body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._body.setObjectName("ChatBubbleText")
        column.addWidget(self._body)
        self._column = column

    def set_text(self, text: str) -> None:
        """Replace the bubble's text."""
        self._body.setText(text)

    def text(self) -> str:
        """The bubble's current text."""
        return self._body.text()

    def add_widget(self, widget: QWidget) -> None:
        """Append a widget beneath the text (e.g. a citations row)."""
        self._column.addWidget(widget)


class CitationChip(QPushButton):
    """A clickable chip that navigates to a cited platform source."""

    activated = Signal(object)  # Citation

    def __init__(self, citation: Citation, *, parent: QWidget | None = None) -> None:
        """Initialize the chip.

        Args:
            citation: The citation this chip represents.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._citation = citation
        self.setObjectName("CitationChip")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        kind = citation_kind_label(citation.kind)
        text = citation.label or citation.source_id
        self.setText(f"{kind}: {text}")
        if citation.excerpt:
            self.setToolTip(citation.excerpt)
        self.clicked.connect(self._emit)

    @property
    def citation(self) -> Citation:
        """The citation backing this chip."""
        return self._citation

    def _emit(self) -> None:
        self.activated.emit(self._citation)


class CitationsRow(QWidget):
    """A wrapped row of citation chips beneath an assistant message."""

    citation_clicked = Signal(object)  # Citation

    def __init__(self, citations: tuple[Citation, ...], *, parent: QWidget | None = None) -> None:
        """Initialize the citations row."""
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, 4, 0, 0)
        column.setSpacing(4)
        column.addWidget(label("Sources", role="caption"))
        chips = QHBoxLayout()
        chips.setContentsMargins(0, 0, 0, 0)
        chips.setSpacing(6)
        for citation in citations:
            chip = CitationChip(citation)
            chip.activated.connect(self.citation_clicked.emit)
            chips.addWidget(chip)
        chips.addStretch(1)
        column.addLayout(chips)


class MetadataRow(QLabel):
    """A subtle one-line row of response metadata beneath an answer."""

    def __init__(self, text: str, *, parent: QWidget | None = None) -> None:
        """Initialize the metadata row."""
        super().__init__(text, parent)
        self.setProperty("role", "caption")
        self.setObjectName("ChatMeta")


class TypingIndicator(QFrame):
    """An assistant-side 'thinking' indicator shown while a request is in flight."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the typing indicator."""
        super().__init__(parent)
        self.setObjectName("ChatBubble")
        self.setProperty("role", "assistant")
        row = QHBoxLayout(self)
        row.setContentsMargins(14, 10, 14, 10)
        self._label = QLabel("Copilot is analysing the intelligence\u2026")
        self._label.setObjectName("ChatBubbleText")
        row.addWidget(self._label)


class SuggestedPrompts(QWidget):
    """A row of quick-action chips that submit predefined prompts."""

    prompt_selected = Signal(str)

    def __init__(self, prompts: tuple[str, ...], *, parent: QWidget | None = None) -> None:
        """Initialize the suggested-prompts row.

        Args:
            prompts: The predefined prompt strings.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._row = QHBoxLayout(self)
        self._row.setContentsMargins(0, 0, 0, 0)
        self._row.setSpacing(8)
        self.set_prompts(prompts)

    def set_prompts(self, prompts: tuple[str, ...]) -> None:
        """Replace the displayed prompts."""
        while self._row.count():
            item = self._row.takeAt(0)
            if item is None:
                break
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for prompt in prompts:
            chip = QPushButton(prompt)
            chip.setObjectName("SuggestChip")
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.clicked.connect(lambda _=False, text=prompt: self.prompt_selected.emit(text))
            self._row.addWidget(chip)
        self._row.addStretch(1)


class ChatComposer(QFrame):
    """A multiline input with Enter-to-send and Shift+Enter for a newline."""

    submitted = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the composer."""
        super().__init__(parent)
        self.setObjectName("ChatComposer")
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 8, 10, 8)
        row.setSpacing(8)

        self._input = _ComposerInput(self._submit)
        self._input.setObjectName("ChatInput")
        self._input.setPlaceholderText(
            "Ask the Copilot about a threat, IOC, incident, or the current posture\u2026"
        )
        self._input.setFixedHeight(44)
        row.addWidget(self._input, 1)

        self._send = QPushButton("Send")
        self._send.setObjectName("ChatSend")
        self._send.setCursor(Qt.CursorShape.PointingHandCursor)
        self._send.clicked.connect(self._submit)
        row.addWidget(self._send)

    def _submit(self) -> None:
        text = self._input.toPlainText().strip()
        if not text:
            return
        self.submitted.emit(text)
        self._input.clear()

    def set_enabled_state(self, enabled: bool) -> None:
        """Enable or disable the composer (e.g. while a request is in flight)."""
        self._input.setEnabled(enabled)
        self._send.setEnabled(enabled)

    def focus_input(self) -> None:
        """Move keyboard focus into the input."""
        self._input.setFocus()

    def set_text(self, text: str) -> None:
        """Set the input text (used by suggested prompts)."""
        self._input.setPlainText(text)


class _ComposerInput(QPlainTextEdit):
    """Composer text area: Enter submits, Shift+Enter inserts a newline."""

    def __init__(self, on_submit: Callable[[], None]) -> None:
        super().__init__()
        self._on_submit = on_submit

    def keyPressEvent(self, e: QKeyEvent) -> None:  # noqa: N802 - Qt override
        if e.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if e.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                super().keyPressEvent(e)
                return
            self._on_submit()
            return
        super().keyPressEvent(e)

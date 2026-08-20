"""Gmail Intelligence page (M14).

The analyst-facing Gmail Intelligence workspace — a security investigation
surface, not a mail client. It presents the read-only Gmail connector as a
finished product: a permission-clear connect experience, a connected-account card
with read-only assurance, and, once connected, a **message workspace** where the
analyst can triage the account's messages by AEGIS+ risk, open a message to see
the *existing* analysis and evidence, safely preview untrusted content, and
navigate into the existing Email Investigation, Graph Explorer, and AI Copilot
experiences.

It is a pure view over :class:`~ui.viewmodels.gmail.GmailViewModel`; every backend
call (the browser OAuth flow, synchronization, message listing and detail) happens
off the UI thread, so the page stays responsive. No OAuth token is ever shown, and
message content is rendered as sanitized plain text with links marked untrusted
and never opened automatically.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ui.backend import (
    GmailMessageDetailDTO,
    GmailMessageDTO,
    GmailStatusDTO,
    GmailSyncDTO,
)
from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.text import label
from ui.context import UIContext
from ui.icons import render_icon
from ui.navigation.routes import Route
from ui.pages.base_page import BasePage
from ui.theme.tokens import DARK
from ui.viewmodels.gmail import GmailViewModel

_LOADING = 0
_DISCONNECTED = 1
_CONNECTING = 2
_CONNECTED = 3

_FILTERS: tuple[tuple[str, str], ...] = (
    ("all", "All"),
    ("high_risk", "High Risk"),
    ("suspicious", "Suspicious"),
    ("benign", "Benign"),
    ("unanalyzed", "Unanalyzed"),
)

_BAND_TONE: dict[str, str] = {
    "high_risk": "danger",
    "suspicious": "warning",
    "benign": "success",
    "unanalyzed": "neutral",
}
_BAND_LABEL: dict[str, str] = {
    "high_risk": "HIGH RISK",
    "suspicious": "SUSPICIOUS",
    "benign": "BENIGN",
    "unanalyzed": "UNANALYZED",
}
_STATUS_LABEL: dict[str, str] = {
    "analyzed": "Analyzed",
    "unsupported": "Unsupported",
    "failed": "Analysis failed",
    "transient": "Not analyzed",
}


class GmailPage(BasePage):
    """The Gmail Intelligence integration workspace."""

    def __init__(
        self,
        context: UIContext,
        *,
        parent: QWidget | None = None,
        view_model: GmailViewModel | None = None,
    ) -> None:
        """Build the Gmail Intelligence page.

        Args:
            context: Shared UI dependencies (theme, backend client, navigation).
            parent: Optional Qt parent.
            view_model: Optional pre-built view-model (tests inject a deterministic
                one); by default the page builds its own.
        """
        super().__init__(
            "Gmail Intelligence",
            "Triage your Gmail messages for phishing and threats using the AEGIS+ "
            "email intelligence platform.",
            parent=parent,
        )
        self._context = context
        self._vm = view_model or GmailViewModel(context.backend_client)
        self._active_filter = "all"
        self._current_detail: GmailMessageDetailDTO | None = None

        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_loading_card())
        self._stack.addWidget(self._build_disconnected_card())
        self._stack.addWidget(self._build_connecting_card())
        self._stack.addWidget(self._build_connected_card())
        self.add(self._stack)
        self.add_stretch()

        self._connect_vm()
        self._stack.setCurrentIndex(_LOADING)
        self._vm.refresh_status()

    # --- cards -----------------------------------------------------------

    def _build_loading_card(self) -> QWidget:
        card = Card()
        card.add(label("Checking Gmail connection…", role="muted"))
        return card

    def _build_disconnected_card(self) -> QWidget:
        card = Card()
        row = QHBoxLayout()
        row.setSpacing(14)
        mark = QLabel()
        mark.setPixmap(render_icon("mail", size=32, color=DARK.primary))
        mark.setFixedWidth(40)
        row.addWidget(mark, 0, Qt.AlignmentFlag.AlignTop)

        body = QVBoxLayout()
        body.setSpacing(6)
        body.addWidget(label("Connect your Gmail account", role="h2"))
        body.addWidget(
            label(
                "Let AEGIS+ analyze messages for phishing, malicious links, and "
                "suspicious attachments. AEGIS+ requests read-only access and never "
                "sends, deletes, or modifies your mail.",
                role="muted",
            )
        )
        perm = QHBoxLayout()
        perm.setSpacing(8)
        perm.addWidget(Badge("Read-only Gmail access", tone="info"))
        perm.addStretch(1)
        body.addLayout(perm)
        row.addLayout(body, 1)
        card.content_layout.addLayout(row)

        self._disconnected_error = label("", role="caption")
        self._disconnected_error.setObjectName("FieldError")
        self._disconnected_error.setWordWrap(True)
        self._disconnected_error.setVisible(False)
        card.add(self._disconnected_error)

        actions = QHBoxLayout()
        self._connect_button = Button("Connect Gmail", variant="primary")
        self._connect_button.setMinimumHeight(42)
        self._connect_button.clicked.connect(self._vm.connect_account)
        actions.addWidget(self._connect_button)
        actions.addStretch(1)
        card.content_layout.addLayout(actions)
        return card

    def _build_connecting_card(self) -> QWidget:
        card = Card()
        card.add(label("Connecting Gmail…", role="h2"))
        card.add(
            label(
                "Your secure Google authorization is opening in your default "
                "browser. Complete authorization there and return to AEGIS+.",
                role="muted",
            )
        )
        return card

    def _build_connected_card(self) -> QWidget:
        card = Card()
        header = QHBoxLayout()
        header.setSpacing(12)
        mark = QLabel()
        mark.setPixmap(render_icon("shield", size=28, color=DARK.success))
        header.addWidget(mark)
        title = QVBoxLayout()
        title.setSpacing(2)
        connected_row = QHBoxLayout()
        connected_row.setSpacing(8)
        connected_row.addWidget(label("Gmail Connected", role="h2"))
        connected_row.addWidget(Badge("Read-only", tone="success"))
        connected_row.addStretch(1)
        title.addLayout(connected_row)
        self._account_label = label("", role="muted")
        title.addWidget(self._account_label)
        header.addLayout(title, 1)
        card.content_layout.addLayout(header)

        meta = QHBoxLayout()
        meta.setSpacing(24)
        self._last_sync_label = label("Last synchronized: Never", role="caption")
        meta.addWidget(self._last_sync_label)
        self._monitoring_label = label("Automatic monitoring: OFF", role="caption")
        meta.addWidget(self._monitoring_label)
        meta.addStretch(1)
        card.content_layout.addLayout(meta)

        self._sync_summary = _SyncSummary()
        card.add(self._sync_summary)

        self._connected_error = label("", role="caption")
        self._connected_error.setObjectName("FieldError")
        self._connected_error.setWordWrap(True)
        self._connected_error.setVisible(False)
        card.add(self._connected_error)

        actions = QHBoxLayout()
        self._sync_button = Button("Sync Now", variant="primary")
        self._sync_button.setMinimumHeight(42)
        self._sync_button.clicked.connect(self._vm.sync)
        actions.addWidget(self._sync_button)
        self._disconnect_button = Button("Disconnect", variant="secondary")
        self._disconnect_button.setMinimumHeight(42)
        self._disconnect_button.clicked.connect(self._vm.disconnect_account)
        actions.addWidget(self._disconnect_button)
        actions.addStretch(1)
        card.content_layout.addLayout(actions)

        card.content_layout.addWidget(self._build_workspace())
        return card

    def _build_workspace(self) -> QWidget:
        container = QWidget()
        outer = QVBoxLayout(container)
        outer.setContentsMargins(0, 8, 0, 0)
        outer.setSpacing(10)

        filters = QHBoxLayout()
        filters.setSpacing(6)
        self._filter_buttons: dict[str, Button] = {}
        for key, text in _FILTERS:
            btn = Button(text, variant="ghost")
            btn.setCheckable(True)
            btn.clicked.connect(lambda _=False, k=key: self._on_filter(k))
            self._filter_buttons[key] = btn
            filters.addWidget(btn)
        filters.addStretch(1)
        self._filter_buttons["all"].setChecked(True)
        outer.addLayout(filters)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search messages by sender, subject, or snippet…")
        self._search.returnPressed.connect(self._on_search)
        outer.addWidget(self._search)

        split = QHBoxLayout()
        split.setSpacing(12)
        self._message_list = QListWidget()
        self._message_list.setMinimumWidth(320)
        self._message_list.setMinimumHeight(280)
        self._message_list.currentItemChanged.connect(self._on_row_changed)
        split.addWidget(self._message_list, 2)

        self._detail = _MessageDetail(self._context)
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setWidget(self._detail)
        detail_scroll.setMinimumHeight(280)
        split.addWidget(detail_scroll, 3)
        outer.addLayout(split)
        return container

    # --- view-model integration -----------------------------------------

    def _connect_vm(self) -> None:
        self._vm.status_loaded.connect(self._on_status)
        self._vm.connect_finished.connect(self._on_connect_finished)
        self._vm.disconnect_finished.connect(self._on_disconnect_finished)
        self._vm.sync_finished.connect(self._on_sync_finished)
        self._vm.messages_loaded.connect(self._on_messages_loaded)
        self._vm.message_loaded.connect(self._on_message_loaded)
        self._vm.busy_changed.connect(self._on_busy)

    @property
    def view_model(self) -> GmailViewModel:
        """The page's view-model (exposed for tests)."""
        return self._vm

    def _on_status(self, status: object) -> None:
        if isinstance(status, GmailStatusDTO):
            self._render_status(status)

    def _on_connect_finished(self, status: object) -> None:
        if not isinstance(status, GmailStatusDTO):
            return
        if status.connected:
            self._render_status(status)
        else:
            self._stack.setCurrentIndex(_DISCONNECTED)
            self._show_error(
                self._disconnected_error,
                status.error or "Gmail authorization was not completed.",
            )

    def _on_disconnect_finished(self, status: object) -> None:
        self._stack.setCurrentIndex(_DISCONNECTED)
        self._hide_error(self._disconnected_error)
        self._sync_summary.clear()
        self._message_list.clear()
        self._detail.clear()

    def _on_sync_finished(self, result: object) -> None:
        if not isinstance(result, GmailSyncDTO):
            return
        self._stack.setCurrentIndex(_CONNECTED)
        if not result.ok:
            self._show_error(
                self._connected_error,
                result.error or "Gmail synchronization could not complete.",
            )
            return
        self._hide_error(self._connected_error)
        self._sync_summary.show_result(result)
        if result.synced_at:
            self._last_sync_label.setText(f"Last synchronized: {_format_time(result.synced_at)}")
        self._reload_messages()

    def _on_messages_loaded(self, messages: object) -> None:
        if not isinstance(messages, tuple):
            return
        self._message_list.blockSignals(True)
        self._message_list.clear()
        for message in messages:
            if isinstance(message, GmailMessageDTO):
                self._message_list.addItem(_message_item(message))
        self._message_list.blockSignals(False)
        if self._message_list.count() == 0:
            self._detail.show_empty()

    def _on_message_loaded(self, detail: object) -> None:
        if isinstance(detail, GmailMessageDetailDTO):
            self._current_detail = detail
            self._detail.show_detail(detail)

    def _on_busy(self, busy: bool) -> None:
        current = self._stack.currentIndex()
        if current == _DISCONNECTED and busy:
            self._stack.setCurrentIndex(_CONNECTING)
        for button in (
            self._connect_button,
            self._sync_button,
            self._disconnect_button,
        ):
            button.setEnabled(not busy)
        if current == _CONNECTED:
            self._sync_button.setText("Syncing…" if busy else "Sync Now")

    # --- workspace interaction ------------------------------------------

    def _on_filter(self, key: str) -> None:
        self._active_filter = key
        for band, btn in self._filter_buttons.items():
            btn.setChecked(band == key)
        self._reload_messages()

    def _on_search(self) -> None:
        self._reload_messages()

    def _on_row_changed(self, current: object, _previous: object) -> None:
        if not isinstance(current, QListWidgetItem):
            return
        message_id = current.data(Qt.ItemDataRole.UserRole)
        if isinstance(message_id, str) and message_id:
            self._detail.show_loading()
            self._vm.open_message(message_id)

    def _reload_messages(self) -> None:
        self._vm.load_messages(risk_filter=self._active_filter, search=self._search.text())

    # --- helpers ---------------------------------------------------------

    def _render_status(self, status: GmailStatusDTO) -> None:
        if not status.connected:
            self._stack.setCurrentIndex(_DISCONNECTED)
            return
        self._stack.setCurrentIndex(_CONNECTED)
        self._account_label.setText(status.email_address or "Connected account")
        self._monitoring_label.setText("Automatic monitoring: OFF")
        if status.last_synced_at:
            self._last_sync_label.setText(
                f"Last synchronized: {_format_time(status.last_synced_at)}"
            )
        else:
            self._last_sync_label.setText("Last synchronized: Never")
        self._reload_messages()

    def _show_error(self, widget: QLabel, message: str) -> None:
        widget.setText(message)
        widget.setVisible(True)

    def _hide_error(self, widget: QLabel) -> None:
        widget.clear()
        widget.setVisible(False)


class _SyncSummary(QWidget):
    """A compact summary of the last synchronization result."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the (initially hidden) summary."""
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(6)
        self._headline = label("", role="body")
        layout.addWidget(self._headline)
        chips = QHBoxLayout()
        chips.setSpacing(8)
        self._malicious = Badge("", tone="danger")
        self._suspicious = Badge("", tone="warning")
        self._benign = Badge("", tone="success")
        self._unanalyzed = Badge("", tone="neutral")
        for badge in (self._malicious, self._suspicious, self._benign, self._unanalyzed):
            chips.addWidget(badge)
        chips.addStretch(1)
        self._chips_row = chips
        layout.addLayout(chips)
        self.setVisible(False)

    def show_result(self, result: GmailSyncDTO) -> None:
        """Render a completed synchronization result with the four-state taxonomy."""
        self.setVisible(True)
        could_not = result.unsupported + result.failed
        headline = f"Last sync: {result.retrieved} retrieved · {result.analyzed} analyzed" + (
            f" · {result.duplicates} already seen" if result.duplicates else ""
        )
        if could_not:
            headline += f" · {could_not} could not be analyzed"
        if result.transient:
            headline += f" · {result.transient} will retry"
        self._headline.setText(headline)
        self._malicious.setText(f"{result.malicious} malicious")
        self._suspicious.setText(f"{result.suspicious} suspicious")
        self._benign.setText(f"{result.benign} benign")
        self._unanalyzed.setText(f"{could_not} unsupported/failed")
        self._unanalyzed.setVisible(bool(could_not))

    def clear(self) -> None:
        """Hide the summary."""
        self.setVisible(False)


class _MessageDetail(QWidget):
    """The message analysis + safe preview + navigation panel."""

    def __init__(self, context: UIContext, parent: QWidget | None = None) -> None:
        """Initialize the detail panel."""
        super().__init__(parent)
        self._context = context
        self._current: GmailMessageDetailDTO | None = None
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(4, 4, 4, 4)
        self._layout.setSpacing(8)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.show_empty()

    # --- states ----------------------------------------------------------

    def clear(self) -> None:
        """Reset to the empty state."""
        self.show_empty()

    def show_empty(self) -> None:
        """Show the no-selection placeholder."""
        self._reset()
        self._layout.addWidget(label("Select a message to see its AEGIS+ analysis.", role="muted"))

    def show_loading(self) -> None:
        """Show a loading placeholder."""
        self._reset()
        self._layout.addWidget(label("Loading analysis…", role="muted"))

    def show_detail(self, detail: GmailMessageDetailDTO) -> None:
        """Render the full analysis + safe preview + navigation for a message."""
        self._current = detail
        self._reset()
        if not detail.ok:
            self._layout.addWidget(
                label(detail.error or "This message could not be loaded.", role="muted")
            )
            return
        message = detail.message
        self._add_verdict_header(detail)
        if detail.analysis_error:
            self._layout.addWidget(label(detail.analysis_error, role="muted"))

        if detail.evidence:
            self._layout.addWidget(label("Why this verdict", role="h3"))
            for item in detail.evidence[:8]:
                self._layout.addWidget(label(f"• {item.detail}", role="body"))

        if detail.iocs:
            self._layout.addWidget(label("Indicators (IOCs)", role="h3"))
            self._layout.addWidget(label(", ".join(detail.iocs[:12]), role="caption"))

        if detail.incident_id or detail.campaign_name:
            self._layout.addWidget(label("Correlation", role="h3"))
            if detail.incident_id:
                self._layout.addWidget(
                    label(f"Incident: {detail.incident_title or detail.incident_id}", role="body")
                )
            if detail.campaign_name:
                self._layout.addWidget(label(f"Campaign: {detail.campaign_name}", role="body"))

        if detail.recommendations:
            self._layout.addWidget(label("Suggested handling", role="h3"))
            for rec in detail.recommendations:
                self._layout.addWidget(label(f"• {rec}", role="caption"))

        self._add_preview(detail)
        self._add_actions(detail)
        _ = message  # message fields are surfaced through the verdict header

    # --- sections --------------------------------------------------------

    def _add_verdict_header(self, detail: GmailMessageDetailDTO) -> None:
        message = detail.message
        row = QHBoxLayout()
        row.setSpacing(8)
        band = message.risk_band
        row.addWidget(
            Badge(_BAND_LABEL.get(band, band.upper()), tone=_BAND_TONE.get(band, "neutral"))
        )
        if message.status == "analyzed":
            row.addWidget(label(f"Risk {message.risk_percent}%", role="body"))
            row.addWidget(label(f"Confidence {round(message.confidence * 100)}%", role="caption"))
        else:
            row.addWidget(label(_STATUS_LABEL.get(message.status, message.status), role="caption"))
        row.addStretch(1)
        self._layout.addLayout(row)
        self._layout.addWidget(label(message.subject or "(no subject)", role="h3"))
        self._layout.addWidget(label(f"From: {message.sender}", role="caption"))

    def _add_preview(self, detail: GmailMessageDetailDTO) -> None:
        preview = detail.preview
        if preview is None:
            return
        self._layout.addWidget(label("Safe preview", role="h3"))
        if preview.error:
            self._layout.addWidget(label(preview.error, role="muted"))
            return
        note = Badge("Untrusted content — links are not opened", tone="warning")
        self._layout.addWidget(note)
        if preview.to:
            self._layout.addWidget(label(f"To: {', '.join(preview.to)}", role="caption"))
        if preview.date:
            self._layout.addWidget(label(f"Date: {preview.date}", role="caption"))
        body = label(preview.plain_body[:4000] or "(no text body)", role="body")
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._layout.addWidget(body)
        if preview.urls:
            self._layout.addWidget(label("Links (untrusted, not clickable)", role="h3"))
            for url in preview.urls[:20]:
                item = label(url.url, role="caption")
                item.setWordWrap(True)
                item.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                self._layout.addWidget(item)
        if preview.attachments:
            self._layout.addWidget(label("Attachments", role="h3"))
            for att in preview.attachments:
                self._layout.addWidget(label(f"• {att}", role="caption"))

    def _add_actions(self, detail: GmailMessageDetailDTO) -> None:
        actions = QHBoxLayout()
        actions.setSpacing(8)
        scan_id = detail.message.scan_id
        if scan_id:
            investigate = Button("Open Investigation", variant="primary")
            investigate.clicked.connect(
                lambda: self._context.go_to(
                    Route.EMAIL_SCANNER, {"scan_id": scan_id, "origin": Route.GMAIL}
                )
            )
            actions.addWidget(investigate)
        if detail.artifact_id:
            graph = Button("Open in Graph Explorer", variant="secondary")
            graph.clicked.connect(
                lambda: self._context.go_to(
                    Route.GRAPH_EXPLORER,
                    {"focus": detail.artifact_id, "origin": Route.GMAIL},
                )
            )
            actions.addWidget(graph)
        copilot = Button("Ask Copilot", variant="secondary")
        copilot.clicked.connect(lambda: self._ask_copilot(detail))
        actions.addWidget(copilot)
        actions.addStretch(1)
        self._layout.addLayout(actions)

    def _ask_copilot(self, detail: GmailMessageDetailDTO) -> None:
        if detail.incident_id:
            payload: dict[str, object] = {
                "focus": detail.incident_id,
                "kind": "incident",
                "origin": Route.GMAIL,
            }
        elif detail.message.sender:
            payload = {
                "focus": detail.message.sender,
                "kind": "artifact",
                "origin": Route.GMAIL,
            }
        else:
            return
        self._context.go_to(Route.COPILOT, payload)

    def _reset(self) -> None:
        _clear_layout(self._layout)


def _clear_layout(layout: QVBoxLayout | QHBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item is None:
            continue
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
            continue
        child = item.layout()
        if isinstance(child, QVBoxLayout | QHBoxLayout):
            _clear_layout(child)


def _message_item(message: GmailMessageDTO) -> QListWidgetItem:
    band = message.risk_band
    if message.status == "analyzed":
        marker = f"{message.risk_percent:>3}%"
    else:
        marker = _STATUS_LABEL.get(message.status, message.status)
    sender = (message.sender or "(unknown sender)")[:32]
    subject = (message.subject or "(no subject)")[:48]
    text = f"[{_BAND_LABEL.get(band, band.upper())}]  {marker}  {sender}  —  {subject}"
    item = QListWidgetItem(text)
    item.setData(Qt.ItemDataRole.UserRole, message.message_id)
    return item


def _format_time(iso: str) -> str:
    """Render an ISO timestamp as a friendly local string (best-effort)."""
    from datetime import datetime

    try:
        moment = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    return moment.strftime("%d %b %Y, %H:%M")

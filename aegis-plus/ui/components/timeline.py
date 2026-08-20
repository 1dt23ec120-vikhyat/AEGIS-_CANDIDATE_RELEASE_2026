"""Timeline and status-state components.

A :class:`TimelineView` renders SOC activity as a vertical, icon-led timeline
with a connecting rail, and :class:`StatusPanel` / :class:`SkeletonPanel` give the
dashboard professional empty, loading, and recovery states so it never presents a
raw error string to an analyst.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.cards import Card
from ui.components.text import label
from ui.icons import render_icon
from ui.theme import ThemeManager
from ui.theme.tokens import Palette

_SEVERITY_ATTR = {
    "critical": "danger",
    "high": "warning",
    "medium": "info",
    "info": "text_muted",
}
_KIND_ICONS = {
    "email_analysis": "mail",
    "url_analysis": "globe",
    "threat_blocked": "shield",
    "campaign_created": "report",
    "incident_created": "alert",
    "detection_correlated": "chip",
    "status_changed": "settings",
    "comment_added": "report",
    "assignment_updated": "settings",
}
_DEFAULT_ICON = "bell"


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """One rendered timeline row."""

    timestamp: str
    title: str
    detail: str
    severity: str = "info"
    kind: str = ""
    artifact_type: str = ""
    relative: str = ""
    group: str = ""
    extra: str = ""


class TimelineView(QWidget):
    """A vertical timeline with icon markers and a connecting rail."""

    def __init__(
        self,
        theme_manager: ThemeManager,
        entries: Sequence[TimelineEntry],
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the timeline.

        Args:
            theme_manager: Supplies palette colours.
            entries: Rows to render, newest first.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        palette = theme_manager.theme.palette
        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)

        current_group = ""
        for index, entry in enumerate(entries):
            if entry.group and entry.group != current_group:
                current_group = entry.group
                header = label(entry.group.upper(), role="caption")
                header.setStyleSheet(
                    f"color: {palette.text_subtle}; font-weight: 700; padding-top: 6px;"
                )
                column.addWidget(header)
            column.addWidget(
                self._build_row(theme_manager, entry, is_last=index == len(entries) - 1)
            )

    def _build_row(
        self, theme_manager: ThemeManager, entry: TimelineEntry, *, is_last: bool
    ) -> QWidget:
        """Render one timeline row: severity marker, rail, and body."""
        palette = theme_manager.theme.palette
        accent: str = getattr(palette, _SEVERITY_ATTR.get(entry.severity, "text_muted"))
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(self._build_rail(palette, accent, entry, is_last=is_last))
        layout.addWidget(self._build_body(entry), stretch=1)
        return row

    @staticmethod
    def _build_rail(
        palette: Palette, accent: str, entry: TimelineEntry, *, is_last: bool
    ) -> QWidget:
        rail = QWidget()
        rail.setFixedWidth(34)
        rail_layout = QVBoxLayout(rail)
        rail_layout.setContentsMargins(0, 2, 0, 0)
        rail_layout.setSpacing(0)
        marker = QLabel()
        marker.setPixmap(
            render_icon(_KIND_ICONS.get(entry.kind, _DEFAULT_ICON), size=16, color=accent)
        )
        marker.setFixedSize(28, 28)
        marker.setAlignment(Qt.AlignmentFlag.AlignCenter)
        marker.setStyleSheet(
            f"border-radius: 14px; background-color: {palette.surface_alt};"
            f"border: 1px solid {accent};"
        )
        rail_layout.addWidget(marker)
        if not is_last:
            line = QLabel()
            line.setFixedWidth(2)
            line.setMinimumHeight(22)
            line.setStyleSheet(f"background-color: {palette.border};")
            rail_layout.addWidget(line, alignment=Qt.AlignmentFlag.AlignHCenter)
        rail_layout.addStretch(1)
        return rail

    @staticmethod
    def _build_body(entry: TimelineEntry) -> QWidget:
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 2, 0, 14)
        body_layout.setSpacing(2)
        head = QHBoxLayout()
        head.setSpacing(8)
        title = label(entry.title, role="body")
        title.setStyleSheet("font-weight: 600;")
        head.addWidget(title)
        if entry.artifact_type:
            head.addWidget(Badge(entry.artifact_type.upper(), tone="info"))
        head.addStretch(1)
        stamp = label(entry.relative or entry.timestamp, role="caption")
        stamp.setToolTip(entry.timestamp)
        head.addWidget(stamp)
        body_layout.addLayout(head)
        detail = label(entry.detail, role="caption")
        detail.setWordWrap(True)
        body_layout.addWidget(detail)
        if entry.extra:
            toggle = Button("Details", variant="secondary")
            extra = label(entry.extra, role="caption")
            extra.setWordWrap(True)
            extra.setVisible(False)
            toggle.clicked.connect(lambda _=False, w=extra: w.setVisible(w.isHidden()))
            actions = QHBoxLayout()
            actions.addWidget(toggle)
            actions.addStretch(1)
            body_layout.addLayout(actions)
            body_layout.addWidget(extra)
        return body


class StatusPanel(Card):
    """A professional empty, waiting, or recovery state."""

    def __init__(
        self,
        theme_manager: ThemeManager,
        *,
        title: str,
        message: str,
        icon_name: str = "shield",
        tone: str = "neutral",
        parent: QWidget | None = None,
    ) -> None:
        """Build a status panel.

        Args:
            theme_manager: Supplies palette colours.
            title: Short headline, e.g. ``"No incidents detected"``.
            message: Supporting explanation.
            icon_name: Registered icon.
            tone: ``neutral``, ``success``, ``warning`` or ``danger``.
            parent: Optional Qt parent.
        """
        super().__init__(parent=parent)
        palette = theme_manager.theme.palette
        accent: str = {
            "success": palette.success,
            "warning": palette.warning,
            "danger": palette.danger,
        }.get(tone, palette.text_muted)

        row = QHBoxLayout()
        row.setSpacing(12)
        glyph = QLabel()
        glyph.setPixmap(render_icon(icon_name, size=22, color=accent))
        glyph.setFixedSize(40, 40)
        glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        glyph.setStyleSheet(f"border-radius: 12px; background-color: {palette.surface_alt};")
        row.addWidget(glyph)

        text = QVBoxLayout()
        text.setSpacing(2)
        heading = label(title, role="body")
        heading.setStyleSheet("font-weight: 600;")
        text.addWidget(heading)
        body = label(message, role="caption")
        body.setWordWrap(True)
        text.addWidget(body)
        row.addLayout(text, stretch=1)
        self.content_layout.addLayout(row)


class SkeletonPanel(Card):
    """Placeholder bars shown while the overview is loading."""

    def __init__(
        self,
        theme_manager: ThemeManager,
        *,
        rows: int = 3,
        parent: QWidget | None = None,
    ) -> None:
        """Build a skeleton loader.

        Args:
            theme_manager: Supplies palette colours.
            rows: How many placeholder bars to render.
            parent: Optional Qt parent.
        """
        super().__init__(parent=parent)
        palette = theme_manager.theme.palette
        widths = (0.45, 0.85, 0.65, 0.75, 0.55)
        for index in range(rows):
            bar = QLabel()
            bar.setFixedHeight(12 if index else 18)
            bar.setMinimumWidth(int(360 * widths[index % len(widths)]))
            bar.setStyleSheet(f"border-radius: 6px; background-color: {palette.surface_alt};")
            self.add(bar)

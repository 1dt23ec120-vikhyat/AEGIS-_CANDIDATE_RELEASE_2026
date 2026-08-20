"""SOC entity cards.

Clickable, severity-accented cards for the two entities an analyst triages from
the command centre: incidents and campaigns. Each surfaces the facts needed to
decide whether to open an investigation, and emits :attr:`clicked` - from a click
anywhere on the card, or from Enter/Space when focused - so the dashboard can
drill through.

Pure presentation; the caller supplies already-aggregated values. Fields the
platform does not report are shown as "Not reported" rather than fabricated.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent, QMouseEvent
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QWidget

from ui.components.badges import Badge
from ui.components.text import label
from ui.components.tiles import NOT_REPORTED, InteractiveCard, tone_color
from ui.theme import ThemeManager

_SEVERITY_TONE = {
    "critical": "danger",
    "high": "danger",
    "medium": "warning",
    "low": "info",
}
_STATUS_TONE = {
    "open": "danger",
    "investigating": "warning",
    "contained": "info",
    "resolved": "success",
    "false_positive": "neutral",
}
_HIGH_RISK = 80
_MEDIUM_RISK = 50
_ACCENT_BAR = 3
_AVATAR = 28
_FIELD_COLUMNS = 2


def risk_tone(risk_percent: int) -> str:
    """Map a risk percentage onto a severity tone."""
    if risk_percent >= _HIGH_RISK:
        return "danger"
    if risk_percent >= _MEDIUM_RISK:
        return "warning"
    return "info"


class _ClickableCard(InteractiveCard):
    """A card that reports activation by mouse or keyboard."""

    clicked = Signal()

    def __init__(self, theme_manager: ThemeManager, *, parent: QWidget | None = None) -> None:
        """Initialize the clickable card."""
        super().__init__(theme_manager, parent=parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt override
        """Emit :attr:`clicked` on a left-button press anywhere on the card."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802 - Qt override
        """Activate the card with Enter or Space for keyboard users."""
        if event.key() in (
            Qt.Key.Key_Return,
            Qt.Key.Key_Enter,
            Qt.Key.Key_Space,
        ):
            self.clicked.emit()
            return
        super().keyPressEvent(event)


def _accent_bar(color: str) -> QLabel:
    bar = QLabel()
    bar.setFixedHeight(_ACCENT_BAR)
    bar.setStyleSheet(f"background-color: {color}; border-radius: 2px;")
    return bar


def _avatar(theme_manager: ThemeManager, owner: str) -> QLabel:
    palette = theme_manager.theme.palette
    initial = owner.strip()[:1].upper() if owner.strip() else "?"
    chip = QLabel(initial)
    chip.setFixedSize(_AVATAR, _AVATAR)
    chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
    background = palette.primary_soft if owner.strip() else palette.surface_alt
    color = palette.primary if owner.strip() else palette.text_subtle
    chip.setStyleSheet(
        f"border-radius: {_AVATAR // 2}px; background-color: {background};"
        f" color: {color}; font-weight: 700;"
    )
    chip.setToolTip(f"Owner: {owner}" if owner.strip() else "Unassigned")
    return chip


def _field(theme_manager: ThemeManager, caption: str, value: str) -> QWidget:
    holder = QWidget()
    layout = QHBoxLayout(holder)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(theme_manager.theme.spacing.sm)
    layout.addWidget(label(caption, role="caption"))
    text = label(value, role="body")
    if value == NOT_REPORTED:
        text.setStyleSheet(f"color: {theme_manager.theme.palette.text_subtle};")
    layout.addWidget(text)
    layout.addStretch(1)
    return holder


class IncidentCard(_ClickableCard):
    """An incident summarised for triage."""

    def __init__(  # noqa: PLR0913 - a presentation card with many displayed fields
        self,
        theme_manager: ThemeManager,
        *,
        title: str,
        category: str,
        risk_percent: int,
        status: str,
        priority: str,
        owner: str,
        affected_users: int,
        detections: int,
        age: str,
        parent: QWidget | None = None,
    ) -> None:
        """Build an incident card."""
        super().__init__(theme_manager, parent=parent)
        theme = theme_manager.theme
        tone = risk_tone(risk_percent)
        accent = tone_color(theme_manager, tone)
        self.setMinimumHeight(212)
        self.content_layout.setSpacing(theme.spacing.sm)
        self.setToolTip(f"{title} - {risk_percent}% risk. Open investigation.")
        self.setAccessibleName(f"Incident {title}")
        self.content_layout.insertWidget(0, _accent_bar(accent))

        head = QHBoxLayout()
        head.setSpacing(theme.spacing.sm)
        head.addWidget(Badge(priority.upper(), tone=_SEVERITY_TONE.get(priority, "info")))
        head.addWidget(
            Badge(
                status.replace("_", " ").upper(),
                tone=_STATUS_TONE.get(status, "neutral"),
            )
        )
        head.addStretch(1)
        risk = label(f"{risk_percent}%", role="h2")
        risk.setStyleSheet(f"color: {accent}; font-weight: 700;")
        head.addWidget(risk)
        self.content_layout.addLayout(head)

        heading = label(title, role="body")
        heading.setStyleSheet("font-weight: 600;")
        heading.setWordWrap(True)
        self.add(heading)
        self.add(label(category.replace("_", " ").title(), role="caption"))

        owner_row = QHBoxLayout()
        owner_row.setSpacing(theme.spacing.sm)
        owner_row.addWidget(_avatar(theme_manager, owner))
        owner_row.addWidget(label(owner or "Unassigned", role="caption"))
        owner_row.addStretch(1)
        owner_row.addWidget(label(age, role="caption"))
        self.content_layout.addLayout(owner_row)

        grid = QGridLayout()
        grid.setContentsMargins(0, theme.spacing.xs, 0, 0)
        grid.setHorizontalSpacing(theme.spacing.lg)
        grid.setVerticalSpacing(theme.spacing.xs)
        grid.addWidget(_field(theme_manager, "Users", str(affected_users)), 0, 0)
        grid.addWidget(_field(theme_manager, "Detections", str(detections)), 0, 1)
        self.content_layout.addLayout(grid)
        self.add(label("Select to open the investigation", role="caption"))


class CampaignCard(_ClickableCard):
    """A campaign summarised for situational awareness."""

    def __init__(  # noqa: PLR0913 - a presentation card with many displayed fields
        self,
        theme_manager: ThemeManager,
        *,
        name: str,
        category: str,
        risk_percent: int,
        occurrences: int,
        affected_users: int,
        first_seen: str,
        last_seen: str,
        growth: str = "",
        incident_count: str = NOT_REPORTED,
        status: str = "Active",
        parent: QWidget | None = None,
    ) -> None:
        """Build a campaign card."""
        super().__init__(theme_manager, parent=parent)
        theme = theme_manager.theme
        tone = risk_tone(risk_percent)
        accent = tone_color(theme_manager, tone)
        self.setMinimumHeight(212)
        self.content_layout.setSpacing(theme.spacing.sm)
        self.setToolTip(f"{name} - {occurrences} detection(s), {risk_percent}% risk.")
        self.setAccessibleName(f"Campaign {name}")
        self.content_layout.insertWidget(0, _accent_bar(accent))

        head = QHBoxLayout()
        head.setSpacing(theme.spacing.sm)
        head.addWidget(Badge(category.replace("_", " ").upper(), tone="info"))
        head.addWidget(Badge(status.upper(), tone="warning"))
        head.addStretch(1)
        risk = label(f"{risk_percent}%", role="h2")
        risk.setStyleSheet(f"color: {accent}; font-weight: 700;")
        head.addWidget(risk)
        self.content_layout.addLayout(head)

        heading = label(name, role="body")
        heading.setStyleSheet("font-weight: 600;")
        heading.setWordWrap(True)
        self.add(heading)

        if growth:
            growth_row = QHBoxLayout()
            growth_row.setSpacing(theme.spacing.xs)
            arrow = label("\u25b2", role="caption")
            arrow.setStyleSheet(f"color: {theme.palette.warning};")
            growth_row.addWidget(arrow)
            growth_row.addWidget(label(growth, role="caption"))
            growth_row.addStretch(1)
            growth_row.addWidget(label(last_seen, role="caption"))
            self.content_layout.addLayout(growth_row)

        grid = QGridLayout()
        grid.setContentsMargins(0, theme.spacing.xs, 0, 0)
        grid.setHorizontalSpacing(theme.spacing.lg)
        grid.setVerticalSpacing(theme.spacing.xs)
        grid.addWidget(_field(theme_manager, "Detections", str(occurrences)), 0, 0)
        grid.addWidget(_field(theme_manager, "Users", str(affected_users)), 0, 1)
        grid.addWidget(_field(theme_manager, "Incidents", incident_count), 1, 0)
        grid.addWidget(_field(theme_manager, "First seen", first_seen), 1, 1)
        self.content_layout.addLayout(grid)

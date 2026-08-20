"""SOC tile components.

Presentation widgets for the command centre's executive overview and platform
health. Both tiles are keyboard focusable, carry tooltips, and standardize on the
shared spacing and radius tokens so every card aligns to the same grid.

These are pure presentation - they render values supplied by the caller and hold
no data-access or detection logic. Where a value is genuinely unavailable the
tile says so explicitly rather than inventing one.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QWidget

from ui.components.cards import Card
from ui.components.text import label
from ui.icons import render_icon
from ui.theme import ThemeManager

NOT_REPORTED = "Not reported"

_TREND_GLYPH = {"up": "\u25b2", "down": "\u25bc", "flat": "\u2013"}
_TONE_ATTR = {
    "danger": "danger",
    "warning": "warning",
    "success": "success",
    "info": "info",
    "neutral": "text_muted",
}
_STATUS_TONE = {
    "healthy": "success",
    "operational": "success",
    "degraded": "warning",
    "disabled": "warning",
    "unhealthy": "danger",
    "offline": "danger",
}
_ICON_CHIP = 34
_ICON_SIZE = 20
_DOT = 10
_FIELD_COLUMNS = 2


def tone_color(theme_manager: ThemeManager, tone: str) -> str:
    """Resolve a severity tone to a palette colour."""
    palette = theme_manager.theme.palette
    color: str = getattr(palette, _TONE_ATTR.get(tone, "text_muted"))
    return color


def status_tone(status: str) -> str:
    """Map a reported status string onto a severity tone."""
    return _STATUS_TONE.get(status.lower(), "danger")


class InteractiveCard(Card):
    """A card with hover and keyboard-focus affordances."""

    def __init__(self, theme_manager: ThemeManager, *, parent: QWidget | None = None) -> None:
        """Apply hover and focus styling from the shared palette."""
        super().__init__(parent=parent)
        palette = theme_manager.theme.palette
        radius = theme_manager.theme.radii.lg
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setStyleSheet(
            f"QFrame#Card {{ border-radius: {radius}px; }}"
            f"QFrame#Card:hover {{ border: 1px solid {palette.border_strong};"
            f" background-color: {palette.elevated}; }}"
            f"QFrame#Card:focus {{ border: 1px solid {palette.primary}; }}"
        )


class MetricTile(InteractiveCard):
    """A headline metric: icon, value, description and trend."""

    def __init__(
        self,
        theme_manager: ThemeManager,
        *,
        metric: str,
        value: str,
        icon_name: str = "shield",
        tone: str = "neutral",
        description: str = "",
        trend: str = "",
        trend_direction: str = "flat",
        parent: QWidget | None = None,
    ) -> None:
        """Build a metric tile.

        Args:
            theme_manager: Supplies palette, spacing and radius tokens.
            metric: The metric name shown above the value.
            value: The headline value.
            icon_name: Registered icon rendered in the accent chip.
            tone: Severity tone driving the accent colour.
            description: A concise one-line explanation.
            trend: Short trend text, e.g. ``"3 vs yesterday"``.
            trend_direction: ``up``, ``down`` or ``flat``.
            parent: Optional Qt parent.
        """
        super().__init__(theme_manager, parent=parent)
        theme = theme_manager.theme
        palette = theme.palette
        accent = tone_color(theme_manager, tone)
        self.setMinimumWidth(216)
        self.setMinimumHeight(150)
        self.content_layout.setSpacing(theme.spacing.sm)
        self.setToolTip(f"{metric}: {value}" + (f" - {description}" if description else ""))
        self.setAccessibleName(f"{metric} {value}")

        head = QHBoxLayout()
        head.setSpacing(theme.spacing.md)
        chip = QLabel()
        chip.setPixmap(render_icon(icon_name, size=_ICON_SIZE, color=accent))
        chip.setFixedSize(_ICON_CHIP, _ICON_CHIP)
        chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        chip.setStyleSheet(
            f"border-radius: {theme.radii.md}px; background-color: {palette.surface_alt};"
        )
        head.addWidget(chip)
        head.addWidget(label(metric.upper(), role="caption"))
        head.addStretch(1)
        self.content_layout.addLayout(head)

        value_label = label(value, role="h2")
        value_label.setStyleSheet(f"color: {accent}; font-size: 28px; font-weight: 700;")
        self.add(value_label)

        if trend:
            footer = QHBoxLayout()
            footer.setSpacing(theme.spacing.xs)
            glyph = label(_TREND_GLYPH.get(trend_direction, "\u2013"), role="caption")
            glyph_color = {"up": palette.danger, "down": palette.success}.get(
                trend_direction, palette.text_muted
            )
            glyph.setStyleSheet(f"color: {glyph_color};")
            footer.addWidget(glyph)
            footer.addWidget(label(trend, role="caption"))
            footer.addStretch(1)
            self.content_layout.addLayout(footer)

        if description:
            self.add(label(description, role="caption"))


class HealthTile(InteractiveCard):
    """A platform subsystem rendered as a diagnostic card."""

    def __init__(
        self,
        theme_manager: ThemeManager,
        *,
        name: str,
        status: str,
        detail: str,
        checked_at: str = "",
        version: str = "",
        latency: str = "",
        mode: str = "",
        parent: QWidget | None = None,
    ) -> None:
        """Build a health tile.

        Unavailable diagnostics are reported as "Not reported" rather than being
        omitted or fabricated, so an analyst can distinguish "healthy" from
        "unknown".

        Args:
            theme_manager: Supplies palette, spacing and radius tokens.
            name: Subsystem name.
            status: Reported status (``healthy``, ``degraded``, ...).
            detail: Supporting detail line.
            checked_at: When the status was observed.
            version: Subsystem version, when reported.
            latency: Observed latency, when reported.
            mode: Operating mode, when reported.
            parent: Optional Qt parent.
        """
        super().__init__(theme_manager, parent=parent)
        theme = theme_manager.theme
        tone = status_tone(status)
        accent = tone_color(theme_manager, tone)
        self.setMinimumWidth(268)
        self.setMinimumHeight(170)
        self.content_layout.setSpacing(theme.spacing.sm)
        self.setToolTip(f"{name}: {status} - {detail}")
        self.setAccessibleName(f"{name} {status}")

        head = QHBoxLayout()
        head.setSpacing(theme.spacing.sm)
        dot = QLabel()
        dot.setFixedSize(_DOT, _DOT)
        dot.setStyleSheet(f"border-radius: {_DOT // 2}px; background-color: {accent};")
        head.addWidget(dot)
        title = label(name.replace("-", " ").replace("_", " ").title(), role="body")
        title.setStyleSheet("font-weight: 600;")
        head.addWidget(title)
        head.addStretch(1)
        state = label(status.title(), role="caption")
        state.setStyleSheet(f"color: {accent}; font-weight: 600;")
        head.addWidget(state)
        self.content_layout.addLayout(head)

        detail_label = label(detail, role="caption")
        detail_label.setWordWrap(True)
        self.add(detail_label)

        grid = QGridLayout()
        grid.setContentsMargins(0, theme.spacing.xs, 0, 0)
        grid.setHorizontalSpacing(theme.spacing.lg)
        grid.setVerticalSpacing(theme.spacing.xs)
        fields = (
            ("Version", version or NOT_REPORTED),
            ("Latency", latency or NOT_REPORTED),
            ("Mode", mode or NOT_REPORTED),
            ("Last check", checked_at or NOT_REPORTED),
        )
        for index, (caption, text) in enumerate(fields):
            row, column = divmod(index, _FIELD_COLUMNS)
            grid.addWidget(label(caption, role="caption"), row, column * 2)
            value = label(text, role="caption")
            if text == NOT_REPORTED:
                value.setStyleSheet(f"color: {theme.palette.text_subtle};")
            grid.addWidget(value, row, column * 2 + 1)
        self.content_layout.addLayout(grid)

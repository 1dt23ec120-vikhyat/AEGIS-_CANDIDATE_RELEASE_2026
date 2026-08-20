"""Tests for the SOC presentation components."""

from __future__ import annotations

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QApplication, QLabel, QWidget

from ui.components.soc_cards import CampaignCard, IncidentCard, risk_tone
from ui.components.tiles import NOT_REPORTED, HealthTile, MetricTile
from ui.components.timeline import (
    SkeletonPanel,
    StatusPanel,
    TimelineEntry,
    TimelineView,
)
from ui.theme import ThemeManager, ThemeMode

pytestmark = pytest.mark.ui


def _theme() -> ThemeManager:
    return ThemeManager(ThemeMode.DARK)


def _text(widget: QWidget) -> str:
    labels = list(widget.findChildren(QLabel))
    if isinstance(widget, QLabel):
        labels.append(widget)
    return " | ".join(label.text() for label in labels if label.text())


def test_risk_tone_maps_severity() -> None:
    assert risk_tone(95) == "danger"
    assert risk_tone(60) == "warning"
    assert risk_tone(10) == "info"


def test_metric_tile_renders_value_and_trend(qapp: QApplication) -> None:
    tile = MetricTile(
        _theme(),
        metric="Open incidents",
        value="3",
        tone="danger",
        description="Awaiting analyst action",
        trend="2 vs yesterday",
        trend_direction="up",
    )
    text = _text(tile)
    assert "OPEN INCIDENTS" in text
    assert "3" in text
    assert "Awaiting analyst action" in text
    assert "2 vs yesterday" in text


def test_health_tile_renders_status(qapp: QApplication) -> None:
    tile = HealthTile(
        _theme(),
        name="ml-engine",
        status="healthy",
        detail="LightGBM model loaded",
        checked_at="10:21:48",
    )
    text = _text(tile)
    assert "Ml Engine" in text
    assert "Healthy" in text
    assert "10:21:48" in text


def test_health_tile_reports_unavailable_fields_explicitly(qapp: QApplication) -> None:
    """Unknown diagnostics must be labelled, never fabricated or hidden."""
    tile = HealthTile(_theme(), name="database", status="healthy", detail="connection ok")
    text = _text(tile)
    assert "Version" in text
    assert "Latency" in text
    assert "Mode" in text
    assert NOT_REPORTED in text


def test_health_tile_shows_reported_fields(qapp: QApplication) -> None:
    tile = HealthTile(
        _theme(),
        name="ml-engine",
        status="healthy",
        detail="LightGBM model loaded",
        version="4.7.0",
        latency="12 ms",
        mode="Active",
    )
    text = _text(tile)
    assert "4.7.0" in text
    assert "12 ms" in text
    assert "Active" in text


def test_incident_card_renders_and_emits_click(qapp: QApplication) -> None:
    card = IncidentCard(
        _theme(),
        title="Phishing - Security notice",
        category="credential_harvesting",
        risk_percent=88,
        status="investigating",
        priority="critical",
        owner="alice",
        affected_users=3,
        detections=2,
        age="4m ago",
    )
    text = _text(card)
    assert "Phishing - Security notice" in text
    assert "Credential Harvesting" in text
    assert "alice" in text
    assert "4m ago" in text

    received: list[bool] = []
    card.clicked.connect(lambda: received.append(True))
    card.mousePressEvent(
        QMouseEvent(
            QMouseEvent.Type.MouseButtonPress,
            QPoint(4, 4),
            Qt.MouseButton.LeftButton,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
    )
    assert received == [True]


def test_campaign_card_renders_fields(qapp: QApplication) -> None:
    card = CampaignCard(
        _theme(),
        name="Brand Impersonation: Invoice Overdue",
        category="brand_impersonation",
        risk_percent=84,
        occurrences=3,
        affected_users=3,
        first_seen="10:21:48",
        last_seen="2m ago",
        growth="3 detection(s) so far",
    )
    text = _text(card)
    assert "Brand Impersonation: Invoice Overdue" in text
    assert "BRAND IMPERSONATION" in text
    assert "ACTIVE" in text
    assert "3 detection(s) so far" in text
    assert NOT_REPORTED in text


def test_timeline_renders_entries_in_order(qapp: QApplication) -> None:
    view = TimelineView(
        _theme(),
        [
            TimelineEntry("10:22:10", "Incident created", "Opened from detection", "critical"),
            TimelineEntry("10:21:48", "Email analyzed", "bad@evil.xyz (phishing)", "high"),
        ],
    )
    text = _text(view)
    assert text.index("Incident created") < text.index("Email analyzed")
    assert "10:22:10" in text


def test_timeline_handles_empty_input(qapp: QApplication) -> None:
    assert TimelineView(_theme(), []) is not None


def test_status_panel_renders_message(qapp: QApplication) -> None:
    panel = StatusPanel(
        _theme(),
        title="No incidents detected",
        message="Nothing requires attention.",
        tone="success",
    )
    text = _text(panel)
    assert "No incidents detected" in text
    assert "Nothing requires attention." in text


def test_skeleton_panel_renders_rows(qapp: QApplication) -> None:
    panel = SkeletonPanel(_theme(), rows=4)
    assert len(panel.findChildren(QLabel)) >= 4


def test_incident_card_activates_with_keyboard(qapp: QApplication) -> None:
    """Cards must be reachable and activatable without a mouse."""
    from PySide6.QtGui import QKeyEvent

    card = IncidentCard(
        _theme(),
        title="Phishing - Security notice",
        category="phishing",
        risk_percent=88,
        status="open",
        priority="high",
        owner="",
        affected_users=1,
        detections=1,
        age="1m ago",
    )
    received: list[bool] = []
    card.clicked.connect(lambda: received.append(True))
    card.keyPressEvent(
        QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
    )
    assert received == [True]
    assert card.focusPolicy() == Qt.FocusPolicy.StrongFocus


def test_unassigned_incident_shows_placeholder_owner(qapp: QApplication) -> None:
    card = IncidentCard(
        _theme(),
        title="Unowned incident",
        category="phishing",
        risk_percent=60,
        status="open",
        priority="medium",
        owner="",
        affected_users=1,
        detections=1,
        age="5m ago",
    )
    assert "Unassigned" in _text(card)


def test_timeline_groups_and_expands(qapp: QApplication) -> None:
    view = TimelineView(
        _theme(),
        [
            TimelineEntry(
                "10:22:10",
                "Incident created",
                "Opened from detection",
                "critical",
                relative="2m ago",
                group="Today",
                extra="Incident inc-1",
            ),
            TimelineEntry(
                "09:00:00",
                "Email analyzed",
                "bad@evil.xyz",
                "high",
                relative="1h ago",
                group="Yesterday",
            ),
        ],
    )
    from PySide6.QtWidgets import QPushButton

    text = _text(view)
    assert "TODAY" in text
    assert "YESTERDAY" in text
    assert "2m ago" in text
    # The expandable entry exposes a Details toggle; the collapsed detail is
    # present in the tree but hidden until it is used.
    toggles = [b for b in view.findChildren(QPushButton) if b.text() == "Details"]
    assert len(toggles) == 1
    extras = [w for w in view.findChildren(QLabel) if w.text() == "Incident inc-1"]
    assert extras and extras[0].isHidden()
    toggles[0].click()
    assert not extras[0].isHidden()

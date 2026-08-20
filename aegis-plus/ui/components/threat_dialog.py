"""Threat warning dialog.

A modal shown when the user tries to open a blacklisted URL from within AEGIS+.
It states that the URL was blocked, summarizes the threat, and offers only Cancel
or View Analysis Report - there is deliberately no "Open Anyway" action.
"""

from __future__ import annotations

from PySide6.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout, QWidget

from ui.backend import ThreatEntryDTO
from ui.components.badges import Badge
from ui.components.buttons import Button
from ui.components.text import label
from ui.theme import ThemeManager

_BLOCK_MESSAGE = (
    "This URL has previously been identified as malicious and has been "
    "blocked to protect your system."
)
_VERDICT_TONE = {"legitimate": "success", "suspicious": "warning", "phishing": "danger"}


class ThreatWarningDialog(QDialog):
    """Modal warning that a URL open was blocked."""

    def __init__(
        self,
        threat: ThreatEntryDTO,
        theme_manager: ThemeManager,
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the dialog for a blacklisted threat.

        Args:
            threat: The blacklist entry.
            theme_manager: Theme source for palette colours.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self.setWindowTitle("URL Blocked")
        self.setModal(True)
        self.setMinimumWidth(480)
        palette = theme_manager.theme.palette
        self.setStyleSheet(f"QDialog {{ background: {palette.surface}; }}")

        column = QVBoxLayout(self)
        column.setContentsMargins(28, 24, 28, 24)
        column.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(label("URL Blocked", role="h2"))
        header.addStretch(1)
        header.addWidget(
            Badge(threat.verdict.upper(), tone=_VERDICT_TONE.get(threat.verdict, "danger"))
        )
        column.addLayout(header)

        message = label(_BLOCK_MESSAGE, role="muted")
        message.setWordWrap(True)
        column.addWidget(message)

        reason = threat.indicators[0].detail if threat.indicators else "Malicious URL"
        for name, value in (
            ("Threat level", threat.verdict.title()),
            ("Risk score", f"{threat.risk_percent}%"),
            ("Detection reason", reason),
            ("First detected", threat.first_detected[:10]),
            ("Times detected", str(threat.detection_count)),
        ):
            row = QHBoxLayout()
            row.addWidget(label(name, role="muted"))
            row.addStretch(1)
            value_label = label(value)
            value_label.setWordWrap(True)
            row.addWidget(value_label)
            column.addLayout(row)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = Button("Cancel", variant="secondary")
        cancel.clicked.connect(self.reject)
        view = Button("View Analysis Report", variant="primary")
        view.clicked.connect(self.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(view)
        column.addLayout(buttons)

    @property
    def view_report_requested(self) -> bool:
        """Whether the user chose to view the analysis report."""
        return self.result() == QDialog.DialogCode.Accepted

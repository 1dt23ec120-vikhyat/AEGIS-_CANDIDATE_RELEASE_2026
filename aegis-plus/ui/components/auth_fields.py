"""Authentication form components (M13).

Small, focused widgets composed by the authentication window: a labelled text
field with an inline error line, a password field with a visibility toggle, and a
password-strength meter. They use the shared design tokens and object names so the
stylesheet themes them consistently with the rest of AEGIS+.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from core.security.auth_policy import password_strength_issue
from ui.components.buttons import IconButton
from ui.theme.tokens import DARK


class FormField(QWidget):
    """A labelled single-line field with an inline validation-error line."""

    def __init__(
        self,
        label: str,
        *,
        placeholder: str = "",
        echo: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the field.

        Args:
            label: The caption shown above the input.
            placeholder: Placeholder text for the input.
            echo: Whether to mask the input (password style).
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._label = QLabel(label)
        self._label.setObjectName("FieldLabel")
        layout.addWidget(self._label)

        self._input = QLineEdit()
        self._input.setObjectName("AuthInput")
        self._input.setPlaceholderText(placeholder)
        self._input.setMinimumHeight(44)
        if echo:
            self._input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self._input)

        self._error = QLabel("")
        self._error.setObjectName("FieldError")
        self._error.setWordWrap(True)
        self._error.setFixedHeight(15)
        layout.addWidget(self._error)

    @property
    def input(self) -> QLineEdit:
        """The underlying line edit."""
        return self._input

    def text(self) -> str:
        """Current text."""
        return self._input.text()

    def set_text(self, value: str) -> None:
        """Set the field text."""
        self._input.setText(value)

    def clear(self) -> None:
        """Clear the text and any error."""
        self._input.clear()
        self.clear_error()

    def set_error(self, message: str) -> None:
        """Show an inline error and mark the input invalid."""
        self._error.setText(message)
        self._input.setProperty("invalid", bool(message))
        self._restyle()

    def clear_error(self) -> None:
        """Clear any inline error."""
        self.set_error("")

    def _restyle(self) -> None:
        style = self._input.style()
        style.unpolish(self._input)
        style.polish(self._input)


class PasswordField(QWidget):
    """A password field with a show/hide visibility toggle."""

    def __init__(
        self,
        label: str,
        *,
        placeholder: str = "Enter your password",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the password field."""
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._label = QLabel(label)
        self._label.setObjectName("FieldLabel")
        layout.addWidget(self._label)

        row = QWidget()
        row.setObjectName("PasswordRow")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(0)

        self._input = QLineEdit()
        self._input.setObjectName("AuthInput")
        self._input.setPlaceholderText(placeholder)
        self._input.setEchoMode(QLineEdit.EchoMode.Password)
        self._input.setMinimumHeight(44)
        row_layout.addWidget(self._input, 1)

        self._toggle = IconButton("eye", color=DARK.text_muted, size=18, tooltip="Show password")
        self._toggle.setObjectName("PasswordToggle")
        self._toggle.setCheckable(True)
        self._toggle.setMinimumHeight(44)
        self._toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle.toggled.connect(self._on_toggle)
        row_layout.addWidget(self._toggle)

        layout.addWidget(row)

        self._error = QLabel("")
        self._error.setObjectName("FieldError")
        self._error.setWordWrap(True)
        self._error.setFixedHeight(15)
        layout.addWidget(self._error)

    @property
    def input(self) -> QLineEdit:
        """The underlying line edit."""
        return self._input

    def text(self) -> str:
        """Current password text."""
        return self._input.text()

    def clear(self) -> None:
        """Clear the password and any error."""
        self._input.clear()
        self.clear_error()

    def set_error(self, message: str) -> None:
        """Show an inline error and mark the input invalid."""
        self._error.setText(message)
        self._input.setProperty("invalid", bool(message))
        style = self._input.style()
        style.unpolish(self._input)
        style.polish(self._input)

    def clear_error(self) -> None:
        """Clear any inline error."""
        self.set_error("")

    def _on_toggle(self, shown: bool) -> None:
        self._input.setEchoMode(QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password)
        self._toggle.set_icon_name("eye-off" if shown else "eye")
        self._toggle.set_color(DARK.text_muted)
        self._toggle.setToolTip("Hide password" if shown else "Show password")


class PasswordStrengthMeter(QWidget):
    """A compact strength bar plus a short qualitative label."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the meter (hidden until the first keystroke)."""
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 0)
        layout.setSpacing(4)

        self._bar = QWidget()
        self._bar.setObjectName("StrengthBar")
        self._bar.setFixedHeight(6)
        self._bar.setProperty("level", "empty")
        layout.addWidget(self._bar)

        self._caption = QLabel("")
        self._caption.setObjectName("StrengthCaption")
        layout.addWidget(self._caption)
        self.setVisible(False)

    def evaluate(self, password: str) -> None:
        """Update the meter for ``password`` (hidden when empty)."""
        if not password:
            self.setVisible(False)
            return
        self.setVisible(True)
        level, caption = _strength(password)
        self._bar.setProperty("level", level)
        self._caption.setText(caption)
        self._caption.setProperty("level", level)
        for widget in (self._bar, self._caption):
            style = widget.style()
            style.unpolish(widget)
            style.polish(widget)


_MIN_VISIBLE_LEN = 6
_STRONG_LEN = 14
_ALL_CLASSES = 4


def _strength(password: str) -> tuple[str, str]:
    """Return a ``(level, caption)`` pair for a password."""
    if password_strength_issue(password) is not None:
        if len(password) < _MIN_VISIBLE_LEN:
            return "weak", "Weak"
        return "medium", "Getting there"
    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if len(password) >= _STRONG_LEN and classes == _ALL_CLASSES:
        return "strong", "Strong"
    return "good", "Good"


ValidationHook = Callable[[str], str | None]

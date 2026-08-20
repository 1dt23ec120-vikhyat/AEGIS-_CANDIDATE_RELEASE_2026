"""Theme aggregate.

A :class:`Theme` bundles a palette with the shared typography, spacing, and
radius scales. Themes are values; switching themes means swapping the palette and
re-applying the generated stylesheet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ui.theme.tokens import (
    DARK,
    LIGHT,
    RADII,
    SPACING,
    TYPOGRAPHY,
    Palette,
    Radii,
    Spacing,
    Typography,
)


class ThemeMode(str, Enum):
    """Available theme modes."""

    LIGHT = "light"
    DARK = "dark"


@dataclass(frozen=True, slots=True)
class Theme:
    """A complete theme: palette plus shared scales."""

    mode: ThemeMode
    palette: Palette
    typography: Typography = field(default=TYPOGRAPHY)
    spacing: Spacing = field(default=SPACING)
    radii: Radii = field(default=RADII)

    @property
    def is_dark(self) -> bool:
        """Whether this is a dark theme."""
        return self.mode is ThemeMode.DARK


def build_theme(mode: ThemeMode) -> Theme:
    """Construct the theme for a mode.

    Args:
        mode: The desired theme mode.

    Returns:
        The corresponding :class:`Theme`.
    """
    palette = DARK if mode is ThemeMode.DARK else LIGHT
    return Theme(mode=mode, palette=palette)

"""Theme system.

Token-driven Light/Dark theming with centralized stylesheet generation. All
visual styling derives from :mod:`ui.theme.tokens`; no widget hardcodes colours.
"""

from ui.theme.manager import ThemeManager
from ui.theme.theme import Theme, ThemeMode, build_theme
from ui.theme.tokens import RADII, SPACING, TYPOGRAPHY, Palette

__all__ = [
    "RADII",
    "SPACING",
    "TYPOGRAPHY",
    "Palette",
    "Theme",
    "ThemeManager",
    "ThemeMode",
    "build_theme",
]

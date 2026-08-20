"""Design tokens.

The single source of visual truth for AEGIS+. Colours, typography, spacing, and
radii are defined here as immutable tokens; the stylesheet and painted
components read from them so no widget hardcodes styling. Light and Dark
palettes share the same structure, enabling additional themes later without
touching component code.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Palette:
    """A named set of semantic colours (hex strings)."""

    name: str

    # Surfaces
    bg: str
    surface: str
    surface_alt: str
    sidebar: str
    elevated: str

    # Text
    text: str
    text_muted: str
    text_subtle: str
    text_on_accent: str

    # Brand / accent
    primary: str
    primary_hover: str
    primary_soft: str

    # Semantic
    success: str
    warning: str
    danger: str
    info: str
    success_soft: str
    warning_soft: str
    danger_soft: str
    info_soft: str

    # Lines
    border: str
    border_strong: str

    # Misc
    shadow: str
    scrollbar: str


DARK = Palette(
    name="dark",
    bg="#0B0E14",
    surface="#131823",
    surface_alt="#1A2131",
    sidebar="#0E121B",
    elevated="#1C2434",
    text="#E7EBF3",
    text_muted="#94A0B6",
    text_subtle="#5F6B82",
    text_on_accent="#FFFFFF",
    primary="#4C8DFF",
    primary_hover="#3B7CF0",
    primary_soft="#17223B",
    success="#2FBF71",
    warning="#F5A524",
    danger="#F0506E",
    info="#4C8DFF",
    success_soft="#12261E",
    warning_soft="#2A2113",
    danger_soft="#2A1620",
    info_soft="#17223B",
    border="#222A3A",
    border_strong="#2E3850",
    shadow="#00000066",
    scrollbar="#2A3346",
)


LIGHT = Palette(
    name="light",
    bg="#F4F6FB",
    surface="#FFFFFF",
    surface_alt="#EEF2F9",
    sidebar="#FFFFFF",
    elevated="#FFFFFF",
    text="#151B26",
    text_muted="#5B6577",
    text_subtle="#93A0B4",
    text_on_accent="#FFFFFF",
    primary="#2F6BFF",
    primary_hover="#2358E6",
    primary_soft="#E7EEFF",
    success="#1E9E5A",
    warning="#C77A0A",
    danger="#D93A57",
    info="#2F6BFF",
    success_soft="#E4F6EC",
    warning_soft="#FBF0DC",
    danger_soft="#FCE7EC",
    info_soft="#E7EEFF",
    border="#E2E8F1",
    border_strong="#CED7E4",
    shadow="#1B255315",
    scrollbar="#C6D0DE",
)


@dataclass(frozen=True, slots=True)
class Typography:
    """Font family and size scale (points)."""

    family: str = '"Segoe UI", "Inter", "SF Pro Text", "Helvetica Neue", Arial, sans-serif'
    mono: str = '"JetBrains Mono", "Cascadia Code", "Consolas", monospace'
    display: int = 26
    h1: int = 20
    h2: int = 16
    h3: int = 14
    body: int = 13
    small: int = 12
    caption: int = 11


@dataclass(frozen=True, slots=True)
class Spacing:
    """Spacing scale on an 8px grid (pixels)."""

    xs: int = 4
    sm: int = 8
    md: int = 12
    lg: int = 16
    xl: int = 24
    xxl: int = 32


@dataclass(frozen=True, slots=True)
class Radii:
    """Corner radius scale (pixels)."""

    sm: int = 6
    md: int = 10
    lg: int = 14
    pill: int = 999


TYPOGRAPHY = Typography()
SPACING = Spacing()
RADII = Radii()

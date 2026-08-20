"""Stylesheet generation.

Produces the complete Qt stylesheet (QSS) for a theme from design tokens. All
widget styling flows from here, so components never hardcode colours or metrics.
``string.Template`` is used (``$name`` placeholders) to avoid clashing with the
braces QSS uses.
"""

from __future__ import annotations

from string import Template

from ui.theme.theme import Theme

_QSS = Template(
    """
* {
    font-family: $font;
}
QWidget {
    color: $text;
    font-size: ${fs_body}pt;
    background: transparent;
}
QMainWindow, #Workspace, #WorkspaceScroll, #WorkspaceScroll > QWidget > QWidget {
    background: $bg;
}
QToolTip {
    background: $elevated;
    color: $text;
    border: 1px solid $border_strong;
    border-radius: ${r_sm}px;
    padding: 6px 8px;
}

/* ---- Scrollbars -------------------------------------------------------- */
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical {
    background: $scrollbar; border-radius: 5px; min-height: 32px;
}
QScrollBar::handle:vertical:hover { background: $border_strong; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal {
    background: $scrollbar; border-radius: 5px; min-width: 32px;
}
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QScrollArea { border: none; background: transparent; }

/* ---- Sidebar ----------------------------------------------------------- */
#Sidebar { background: $sidebar; border-right: 1px solid $border; }
#BrandName { font-size: ${fs_h1}pt; font-weight: 700; color: $text; }
#BrandMark { border-radius: ${r_sm}px; background: $primary_soft; }
#NavSectionLabel {
    color: $subtle; font-size: ${fs_caption}pt; font-weight: 700;
    padding: 0px 12px;
}
QPushButton#NavItem {
    text-align: left; border: none; background: transparent; color: $muted;
    border-radius: ${r_md}px; padding: 9px 12px; font-size: ${fs_body}pt;
    font-weight: 500;
}
QPushButton#NavItem:hover { background: $surface_alt; color: $text; }
QPushButton#NavItem:checked {
    background: $primary_soft; color: $primary; font-weight: 600;
}

/* ---- Top bar / status bar --------------------------------------------- */
#TopBar { background: $surface; border-bottom: 1px solid $border; }
#StatusBar { background: $surface; border-top: 1px solid $border; }
#StatusBar QLabel { color: $muted; font-size: ${fs_small}pt; }
#PageTitle { font-size: ${fs_h1}pt; font-weight: 700; color: $text; }

/* ---- Cards ------------------------------------------------------------- */
#Card {
    background: $surface; border: 1px solid $border; border-radius: ${r_lg}px;
}
#Card:hover { border: 1px solid $border_strong; }
#CardFlat { background: $surface_alt; border-radius: ${r_lg}px; }

/* ---- Buttons ----------------------------------------------------------- */
QPushButton {
    border-radius: ${r_md}px; padding: 8px 16px; font-size: ${fs_body}pt;
    font-weight: 600;
}
QPushButton[variant="primary"] {
    background: $primary; color: $on_accent; border: none;
}
QPushButton[variant="primary"]:hover { background: $primary_hover; }
QPushButton[variant="primary"]:disabled { background: $border_strong; color: $subtle; }
QPushButton[variant="secondary"] {
    background: $surface_alt; color: $text; border: 1px solid $border;
}
QPushButton[variant="secondary"]:hover { border: 1px solid $border_strong; }
QPushButton[variant="ghost"] {
    background: transparent; color: $muted; border: none;
}
QPushButton[variant="ghost"]:hover { color: $text; background: $surface_alt; }
QPushButton#IconButton {
    background: transparent; border: none; border-radius: ${r_md}px; padding: 6px;
}
QPushButton#IconButton:hover { background: $surface_alt; }

/* ---- Inputs ------------------------------------------------------------ */
QLineEdit {
    background: $surface_alt; border: 1px solid $border; border-radius: ${r_md}px;
    padding: 8px 12px; color: $text; selection-background-color: $primary;
    selection-color: $on_accent;
}
QLineEdit:focus { border: 1px solid $primary; }
QLineEdit#SearchBar { background: $surface_alt; padding-left: 34px; }

/* ---- Text roles -------------------------------------------------------- */
QLabel[role="display"] { font-size: ${fs_display}pt; font-weight: 700; color: $text; }
QLabel[role="h1"] { font-size: ${fs_h1}pt; font-weight: 700; color: $text; }
QLabel[role="h2"] { font-size: ${fs_h2}pt; font-weight: 600; color: $text; }
QLabel[role="h3"] { font-size: ${fs_h3}pt; font-weight: 600; color: $text; }
QLabel[role="muted"] { color: $muted; }
QLabel[role="subtle"] { color: $subtle; }
QLabel[role="caption"] { color: $muted; font-size: ${fs_caption}pt; }

/* ---- Badges ------------------------------------------------------------ */
QLabel[badge="neutral"] {
    background: $surface_alt; color: $muted; border-radius: ${r_pill}px;
    padding: 3px 10px; font-size: ${fs_caption}pt; font-weight: 700;
}
QLabel[badge="success"] {
    background: $success_soft; color: $success; border-radius: ${r_pill}px;
    padding: 3px 10px; font-size: ${fs_caption}pt; font-weight: 700;
}
QLabel[badge="warning"] {
    background: $warning_soft; color: $warning; border-radius: ${r_pill}px;
    padding: 3px 10px; font-size: ${fs_caption}pt; font-weight: 700;
}
QLabel[badge="danger"] {
    background: $danger_soft; color: $danger; border-radius: ${r_pill}px;
    padding: 3px 10px; font-size: ${fs_caption}pt; font-weight: 700;
}
QLabel[badge="info"] {
    background: $info_soft; color: $info; border-radius: ${r_pill}px;
    padding: 3px 10px; font-size: ${fs_caption}pt; font-weight: 700;
}

/* ---- Tables ------------------------------------------------------------ */
QTableWidget {
    background: $surface; border: 1px solid $border; border-radius: ${r_lg}px;
    gridline-color: transparent; color: $text;
}
QTableWidget::item { padding: 10px 12px; border-bottom: 1px solid $border; }
QTableWidget::item:selected { background: $primary_soft; color: $text; }
QHeaderView::section {
    background: transparent; color: $subtle; border: none;
    border-bottom: 1px solid $border; padding: 10px 12px; font-weight: 700;
    font-size: ${fs_caption}pt;
}
QTableCornerButton::section { background: transparent; border: none; }

/* ---- AI Copilot -------------------------------------------------------- */
#ChatScroll { border: none; background: transparent; }
#ChatBubble[role="assistant"] {
    background: $surface; border: 1px solid $border; border-radius: ${r_lg}px;
}
#ChatBubble[role="user"] {
    background: $primary_soft; border: 1px solid $primary_soft; border-radius: ${r_lg}px;
}
#ChatBubble[role="error"] {
    background: $danger_soft; border: 1px solid $danger; border-radius: ${r_lg}px;
}
#ChatBubbleText { color: $text; font-size: ${fs_body}pt; background: transparent; }
#ChatMeta { color: $subtle; }
QPushButton#CitationChip {
    background: $info_soft; color: $info; border: 1px solid $info_soft;
    border-radius: ${r_pill}px; padding: 4px 12px; font-size: ${fs_caption}pt;
    font-weight: 700;
}
QPushButton#CitationChip:hover { border: 1px solid $primary; }
QPushButton#SuggestChip {
    background: $surface_alt; color: $muted; border: 1px solid $border;
    border-radius: ${r_pill}px; padding: 6px 14px; font-size: ${fs_small}pt;
}
QPushButton#SuggestChip:hover { border: 1px solid $primary; color: $text; }
#ChatComposer {
    background: $surface; border: 1px solid $border; border-radius: ${r_lg}px;
}
#ChatComposer:focus-within { border: 1px solid $primary; }
QPlainTextEdit#ChatInput {
    background: transparent; border: none; color: $text;
    font-size: ${fs_body}pt; selection-background-color: $primary;
    selection-color: $on_accent;
}
QPushButton#ChatSend {
    background: $primary; color: $on_accent; border: none;
    border-radius: ${r_md}px; padding: 8px 20px; font-weight: 700;
}
QPushButton#ChatSend:hover { background: $primary_hover; }
QPushButton#ChatSend:disabled { background: $border_strong; color: $subtle; }

/* ---- Authentication ---------------------------------------------------- */
#AuthWindow { background: $bg; }
#AuthHero {
    background: $sidebar; border-right: 1px solid $border;
}
#HeroWordmark { font-size: 22pt; font-weight: 800; color: $text; letter-spacing: 1px; }
#HeroHeadline {
    font-size: ${fs_display}pt; font-weight: 700; color: $text; line-height: 130%;
}
#HeroSubhead { font-size: ${fs_body}pt; color: $muted; line-height: 150%; }
#HeroPoint { font-size: ${fs_small}pt; color: $muted; }
#HeroFooter { font-size: ${fs_caption}pt; color: $subtle; letter-spacing: 1px; }

#AuthFormPanel { background: $bg; }
#AuthCard {
    background: $surface; border: 1px solid $border; border-radius: ${r_lg}px;
}
#AuthTitle { font-size: ${fs_h1}pt; font-weight: 700; color: $text; }
#AuthSubtitle { font-size: ${fs_small}pt; color: $muted; }
#AuthMuted { font-size: ${fs_small}pt; color: $muted; }
#FieldLabel { font-size: ${fs_small}pt; font-weight: 600; color: $muted; }

QLineEdit#AuthInput {
    background: $surface_alt; border: 1px solid $border; border-radius: ${r_md}px;
    padding: 0 14px; color: $text; font-size: ${fs_body}pt;
}
QLineEdit#AuthInput:focus { border: 1px solid $primary; background: $elevated; }
QLineEdit#AuthInput[invalid="true"] { border: 1px solid $danger; }

#PasswordRow QLineEdit#AuthInput {
    border-top-right-radius: 0; border-bottom-right-radius: 0; border-right: none;
}
QPushButton#PasswordToggle {
    background: $surface_alt; border: 1px solid $border;
    border-top-left-radius: 0; border-bottom-left-radius: 0;
    border-top-right-radius: ${r_md}px; border-bottom-right-radius: ${r_md}px;
    padding: 0 12px;
}
QPushButton#PasswordToggle:hover { background: $elevated; }
QPushButton#PasswordToggle:checked { background: $elevated; }

#FieldError { font-size: ${fs_caption}pt; color: $danger; margin-top: 2px; }
#AuthBanner {
    background: $danger_soft; color: $danger; border: 1px solid $danger;
    border-radius: ${r_md}px; padding: 10px 14px; font-size: ${fs_small}pt;
}
#AuthLink { color: $primary; font-size: ${fs_small}pt; font-weight: 600; }
#AuthLink:hover { color: $primary_hover; }

#StrengthBar { border-radius: 3px; background: $border; }
#StrengthBar[level="weak"] { background: $danger; }
#StrengthBar[level="medium"] { background: $warning; }
#StrengthBar[level="good"] { background: $info; }
#StrengthBar[level="strong"] { background: $success; }
#StrengthCaption { font-size: ${fs_caption}pt; color: $muted; }
#StrengthCaption[level="weak"] { color: $danger; }
#StrengthCaption[level="medium"] { color: $warning; }
#StrengthCaption[level="good"] { color: $info; }
#StrengthCaption[level="strong"] { color: $success; }
"""
)


def build_stylesheet(theme: Theme) -> str:
    """Render the full stylesheet for a theme.

    Args:
        theme: The theme to render.

    Returns:
        A QSS string suitable for ``QApplication.setStyleSheet``.
    """
    p = theme.palette
    t = theme.typography
    r = theme.radii
    return _QSS.substitute(
        font=t.family,
        fs_display=t.display,
        fs_h1=t.h1,
        fs_h2=t.h2,
        fs_h3=t.h3,
        fs_body=t.body,
        fs_small=t.small,
        fs_caption=t.caption,
        bg=p.bg,
        surface=p.surface,
        surface_alt=p.surface_alt,
        sidebar=p.sidebar,
        elevated=p.elevated,
        text=p.text,
        muted=p.text_muted,
        subtle=p.text_subtle,
        on_accent=p.text_on_accent,
        primary=p.primary,
        primary_hover=p.primary_hover,
        primary_soft=p.primary_soft,
        success=p.success,
        warning=p.warning,
        danger=p.danger,
        info=p.info,
        success_soft=p.success_soft,
        warning_soft=p.warning_soft,
        danger_soft=p.danger_soft,
        info_soft=p.info_soft,
        border=p.border,
        border_strong=p.border_strong,
        scrollbar=p.scrollbar,
        r_sm=r.sm,
        r_md=r.md,
        r_lg=r.lg,
        r_pill=r.pill,
    )

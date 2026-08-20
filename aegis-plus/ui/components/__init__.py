"""Reusable UI component library.

A consistent visual language of building blocks - buttons, cards, badges,
inputs, tables, charts, and text - used across the application. Components are
styled centrally by the theme and never hardcode colours.
"""

from ui.components.badges import Badge, StatusDot
from ui.components.buttons import Button, IconButton
from ui.components.cards import Card, StatCard
from ui.components.chart import MiniBarChart
from ui.components.empty_state import EmptyState
from ui.components.inputs import SearchBar
from ui.components.tables import DataTable
from ui.components.text import PageHeader, SectionTitle, label

__all__ = [
    "Badge",
    "Button",
    "Card",
    "DataTable",
    "EmptyState",
    "IconButton",
    "MiniBarChart",
    "PageHeader",
    "SearchBar",
    "SectionTitle",
    "StatCard",
    "StatusDot",
    "label",
]

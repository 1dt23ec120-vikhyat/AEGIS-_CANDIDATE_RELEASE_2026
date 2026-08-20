"""Route definitions.

A single declarative list of navigable destinations. Adding a module is a matter
of adding a :class:`NavEntry` here and registering its page - the sidebar and
router build themselves from this list, so navigation scales without redesign.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Route(str, Enum):
    """Navigable application routes."""

    DASHBOARD = "dashboard"
    URL_SCANNER = "url_scanner"
    EMAIL_SCANNER = "email_scanner"
    FILE_SCANNER = "file_scanner"
    THREAT_INTEL = "threat_intel"
    INCIDENTS = "incidents"
    GRAPH_EXPLORER = "graph_explorer"
    COPILOT = "copilot"
    REPORTS = "reports"
    GMAIL = "gmail"
    AI_MODELS = "ai_models"
    SETTINGS = "settings"


@dataclass(frozen=True, slots=True)
class NavEntry:
    """A sidebar navigation entry."""

    route: Route
    label: str
    icon: str
    section: str


NAVIGATION: list[NavEntry] = [
    NavEntry(Route.DASHBOARD, "Dashboard", "dashboard", "Overview"),
    NavEntry(Route.URL_SCANNER, "URL Scanner", "globe", "Detection"),
    NavEntry(Route.EMAIL_SCANNER, "Email Scanner", "mail", "Detection"),
    NavEntry(Route.FILE_SCANNER, "File Scanner", "file", "Detection"),
    NavEntry(Route.THREAT_INTEL, "Threat Intelligence", "shield", "Operations"),
    NavEntry(Route.INCIDENTS, "Incidents", "alert", "Operations"),
    NavEntry(Route.GRAPH_EXPLORER, "Graph Explorer", "share", "Operations"),
    NavEntry(Route.COPILOT, "AI Copilot", "copilot", "Operations"),
    NavEntry(Route.REPORTS, "Reports", "report", "Operations"),
    NavEntry(Route.GMAIL, "Gmail Intelligence", "mail", "Integrations"),
    NavEntry(Route.AI_MODELS, "AI Models", "chip", "System"),
    NavEntry(Route.SETTINGS, "Settings", "settings", "System"),
]

"""Workspace pages.

Polished, production-looking pages for each module. They present the intended
structure and visual language before business functionality is connected.
"""

from ui.pages.ai_models import AiModelsPage
from ui.pages.copilot import CopilotPage
from ui.pages.dashboard import DashboardPage
from ui.pages.email_scanner import EmailScannerPage
from ui.pages.file_scanner import FileScannerPage
from ui.pages.gmail import GmailPage
from ui.pages.graph_explorer import GraphExplorerPage
from ui.pages.incidents import IncidentsPage
from ui.pages.reports import ReportsPage
from ui.pages.settings import SettingsPage
from ui.pages.threat_intelligence import ThreatIntelligencePage
from ui.pages.url_scanner import UrlScannerPage

__all__ = [
    "AiModelsPage",
    "CopilotPage",
    "DashboardPage",
    "EmailScannerPage",
    "FileScannerPage",
    "GmailPage",
    "GraphExplorerPage",
    "IncidentsPage",
    "ReportsPage",
    "SettingsPage",
    "ThreatIntelligencePage",
    "UrlScannerPage",
]

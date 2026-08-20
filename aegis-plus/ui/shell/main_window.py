"""Main window.

Assembles the application shell - sidebar, top bar, routed workspace, and status
bar - and wires navigation. Pages are registered against routes; selecting a nav
item swaps the workspace page and updates the title, and the router keeps the
sidebar's active item in sync.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ui.backend import BackendHealthPoller
from ui.context import UIContext
from ui.navigation import NAVIGATION, Route, Router, Sidebar
from ui.pages import (
    AiModelsPage,
    CopilotPage,
    DashboardPage,
    EmailScannerPage,
    FileScannerPage,
    GmailPage,
    GraphExplorerPage,
    IncidentsPage,
    ReportsPage,
    SettingsPage,
    ThreatIntelligencePage,
    UrlScannerPage,
)
from ui.shell.status_bar import StatusBar
from ui.shell.top_bar import TopBar

_PAGE_FACTORIES: dict[Route, Callable[[UIContext], QWidget]] = {
    Route.DASHBOARD: DashboardPage,
    Route.URL_SCANNER: UrlScannerPage,
    Route.EMAIL_SCANNER: EmailScannerPage,
    Route.FILE_SCANNER: FileScannerPage,
    Route.THREAT_INTEL: ThreatIntelligencePage,
    Route.INCIDENTS: IncidentsPage,
    Route.GRAPH_EXPLORER: GraphExplorerPage,
    Route.COPILOT: CopilotPage,
    Route.REPORTS: ReportsPage,
    Route.GMAIL: GmailPage,
    Route.AI_MODELS: AiModelsPage,
    Route.SETTINGS: SettingsPage,
}

_TITLES: dict[Route, str] = {entry.route: entry.label for entry in NAVIGATION}


class MainWindow(QMainWindow):
    """The AEGIS+ main application window."""

    logout_requested = Signal()

    def __init__(
        self,
        context: UIContext,
        *,
        environment: str = "Local",
        version: str = "0.1.0",
    ) -> None:
        """Build the main window.

        Args:
            context: Shared UI dependencies.
            environment: Environment label for the status bar.
            version: Version label for the status bar.
        """
        super().__init__()
        self._context = context
        self.setWindowTitle("AEGIS+  -  Phishing & Identity Attack Detection")
        self.setMinimumSize(1160, 740)

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._sidebar = Sidebar(context.theme_manager)
        root.addWidget(self._sidebar)

        right = QWidget()
        right_column = QVBoxLayout(right)
        right_column.setContentsMargins(0, 0, 0, 0)
        right_column.setSpacing(0)

        self._top_bar = TopBar(context.theme_manager)
        self._top_bar.logout_requested.connect(self.logout_requested)
        right_column.addWidget(self._top_bar)

        self._stack = QStackedWidget()
        scroll = QScrollArea()
        scroll.setObjectName("WorkspaceScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self._stack)
        right_column.addWidget(scroll, 1)

        self._status_bar = StatusBar(
            context.theme_manager, environment=environment, version=version
        )
        right_column.addWidget(self._status_bar)

        root.addWidget(right, 1)
        self.setCentralWidget(central)

        self._router = Router(self._stack)
        page_context = replace(context, navigate=self._router.navigate)
        for entry in NAVIGATION:
            self._router.register(entry.route, _PAGE_FACTORIES[entry.route](page_context))

        self._sidebar.route_selected.connect(self._router.navigate)
        self._router.route_changed.connect(self._on_route_changed)

        self._poller = BackendHealthPoller(context.backend_client)
        self._poller.status_changed.connect(self._status_bar.set_backend_status)

        self._sidebar.set_active(Route.DASHBOARD)
        self._router.navigate(Route.DASHBOARD)

    @property
    def router(self) -> Router:
        """The navigation router."""
        return self._router

    def start_services(self) -> None:
        """Start background UI services (backend health polling)."""
        self._poller.start()

    def set_account(self, full_name: str) -> None:
        """Reflect the authenticated account in the shell (avatar initials)."""
        self._top_bar.set_account(full_name)

    def stop_services(self) -> None:
        """Stop background UI services."""
        self._poller.stop()

    def _on_route_changed(self, route: Route) -> None:
        self._sidebar.set_active(route)
        self._top_bar.set_title(_TITLES.get(route, ""))

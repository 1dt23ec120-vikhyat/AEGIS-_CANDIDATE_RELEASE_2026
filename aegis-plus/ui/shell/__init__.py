"""Application shell.

The main window and its chrome - sidebar, top bar, status bar, and splash - that
frame the routed workspace.
"""

from ui.shell.main_window import MainWindow
from ui.shell.splash import SplashScreen
from ui.shell.status_bar import StatusBar
from ui.shell.top_bar import TopBar

__all__ = ["MainWindow", "SplashScreen", "StatusBar", "TopBar"]

"""Desktop entry point.

Assembles and runs the desktop application: creates the QApplication, applies the
theme, shows the splash, and builds the main window pointed at the embedded
backend. The composition root calls :func:`run_desktop`; end-to-end wiring with
the backend lifecycle is completed in the walking skeleton (WP8).
"""

from __future__ import annotations

from PySide6.QtWidgets import QApplication

from ui.backend import BackendClient
from ui.context import UIContext
from ui.shell.auth_flow import DesktopAuthFlow
from ui.shell.main_window import MainWindow
from ui.shell.splash import SplashScreen
from ui.theme import ThemeManager, ThemeMode


def create_application(argv: list[str] | None = None) -> QApplication:
    """Return the QApplication, creating it if necessary.

    Args:
        argv: Optional argument vector.

    Returns:
        The running :class:`~PySide6.QtWidgets.QApplication`.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    application = QApplication(argv if argv is not None else [])
    application.setApplicationName("AEGIS+")
    return application


def build_main_window(
    backend_url: str,
    *,
    mode: ThemeMode = ThemeMode.DARK,
    environment: str = "Local",
    version: str = "0.1.0",
) -> tuple[ThemeManager, MainWindow]:
    """Build the themed main window and its theme manager.

    Requires a live QApplication (create one first via :func:`create_application`).

    Args:
        backend_url: The embedded backend base URL.
        mode: Initial theme mode.
        environment: Environment label for the status bar.
        version: Version label for the status bar.

    Returns:
        A tuple of the theme manager and the main window.
    """
    theme_manager = ThemeManager(mode)
    theme_manager.apply()
    context = UIContext(theme_manager=theme_manager, backend_client=BackendClient(backend_url))
    window = MainWindow(context, environment=environment, version=version)
    return theme_manager, window


def run_desktop(
    backend_url: str,
    *,
    argv: list[str] | None = None,
    mode: ThemeMode = ThemeMode.DARK,
    environment: str = "Local",
    version: str = "0.1.0",
) -> int:
    """Run the desktop application event loop.

    The application opens to the authentication window; the SOC Command Center
    and all protected workspaces are built only after a session is established.

    Args:
        backend_url: The embedded backend base URL.
        argv: Optional argument vector.
        mode: Initial theme mode.
        environment: Environment label for the status bar.
        version: Version label for the status bar.

    Returns:
        The application's exit code.
    """
    application = create_application(argv)
    splash = SplashScreen()
    splash.show()
    application.processEvents()

    theme_manager = ThemeManager(mode)
    theme_manager.apply()
    client = BackendClient(backend_url)

    flow = DesktopAuthFlow(
        theme_manager=theme_manager,
        client=client,
        environment=environment,
        version=version,
    )
    flow.start()
    entrance = flow.auth_window
    if entrance is not None:
        splash.finish(entrance)
    else:
        splash.close()
    # ``flow`` stays referenced by this frame until exec() returns, keeping the
    # windows alive for the lifetime of the event loop.
    return application.exec()

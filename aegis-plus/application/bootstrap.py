"""Application bootstrap.

The entry point that assembles the application: it loads configuration, builds
the dependency container (the composition root), and returns a ready
:class:`Application`. Nothing is started here - the caller controls startup.
"""

from __future__ import annotations

from application.app import Application
from application.dependency_container import DependencyContainer
from application.lifecycle import ApplicationLifecycle
from config import Settings, get_settings


def bootstrap(settings: Settings | None = None) -> Application:
    """Assemble the application.

    Args:
        settings: Optional pre-loaded settings. Loaded from the environment when
            omitted.

    Returns:
        A ready but not-yet-started :class:`Application`.
    """
    resolved_settings = settings or get_settings()
    container = DependencyContainer(resolved_settings)
    lifecycle = ApplicationLifecycle(container)
    return Application(container, lifecycle)

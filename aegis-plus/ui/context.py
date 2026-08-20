"""UI context.

A small dependency bundle passed to shell components and pages, so they receive
their collaborators (theme manager, backend client, navigation) by injection
rather than reaching for globals - mirroring the composition-root discipline in
the UI layer.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ui.backend.client import BackendClient
from ui.theme import ThemeManager


@dataclass(frozen=True, slots=True)
class UIContext:
    """Shared UI dependencies."""

    theme_manager: ThemeManager
    backend_client: BackendClient
    navigate: Callable[..., None] | None = None

    def go_to(self, route: Any, payload: Any = None) -> None:
        """Navigate to ``route`` when navigation is available.

        Pages call this for drill-down. An optional ``payload`` is forwarded to
        the destination page's navigation hook (e.g. to open the Graph Explorer
        focused on an artifact). It is a no-op when the context was built without
        navigation (for example in isolated widget tests).
        """
        if self.navigate is not None:
            if payload is None:
                self.navigate(route)
            else:
                self.navigate(route, payload)

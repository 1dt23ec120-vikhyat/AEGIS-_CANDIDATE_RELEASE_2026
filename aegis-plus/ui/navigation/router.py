"""Routing framework.

A thin controller over a :class:`~PySide6.QtWidgets.QStackedWidget`. Pages are
registered against a :class:`Route`; navigation swaps the visible page and emits
:attr:`route_changed` so the shell (title, sidebar) can stay in sync.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QStackedWidget, QWidget

from ui.navigation.routes import Route


class Router(QObject):
    """Maps routes to stacked pages and controls navigation."""

    route_changed = Signal(object)  # emits Route

    def __init__(self, stack: QStackedWidget, parent: QObject | None = None) -> None:
        """Initialize the router.

        Args:
            stack: The stacked widget hosting the pages.
            parent: Optional Qt parent.
        """
        super().__init__(parent)
        self._stack = stack
        self._indices: dict[Route, int] = {}
        self._current: Route | None = None

    @property
    def current_route(self) -> Route | None:
        """The currently active route, if any."""
        return self._current

    def register(self, route: Route, widget: QWidget) -> None:
        """Register a page widget for a route."""
        self._indices[route] = self._stack.addWidget(widget)

    def navigate(self, route: Route, payload: object = None) -> None:
        """Show the page for ``route`` and notify listeners.

        An optional ``payload`` is delivered to the target page's
        ``on_navigated`` hook (if it defines one), enabling deep links such as
        opening the Graph Explorer focused on a specific artifact. Passing no
        payload preserves the original behaviour exactly.
        """
        if route not in self._indices:
            return
        if route is not self._current:
            self._stack.setCurrentIndex(self._indices[route])
            self._current = route
            self.route_changed.emit(route)
        if payload is not None:
            widget = self._stack.widget(self._indices[route])
            hook = getattr(widget, "on_navigated", None)
            if callable(hook):
                hook(payload)

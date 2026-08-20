"""Navigation framework.

A declarative route registry, a stack-based router, and a self-building sidebar.
Adding a module requires only a new route entry and a registered page.
"""

from ui.navigation.router import Router
from ui.navigation.routes import NAVIGATION, NavEntry, Route
from ui.navigation.sidebar import Sidebar

__all__ = ["NAVIGATION", "NavEntry", "Route", "Router", "Sidebar"]

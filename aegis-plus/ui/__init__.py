"""AEGIS+ desktop UI (PySide6, MVVM).

A modern enterprise application shell: token-driven theming, a reusable component
library, a scalable navigation framework, and polished module pages. The UI
reaches application services only over HTTP via the embedded backend (ADR-002);
it never imports services, infrastructure, AI, or the composition root.
"""

from ui.desktop import build_main_window, create_application, run_desktop

__all__ = ["build_main_window", "create_application", "run_desktop"]

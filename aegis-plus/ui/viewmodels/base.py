"""View-model base.

View-models hold presentation state and expose it to views (pages), keeping data
and formatting out of the widgets themselves (MVVM). As business logic arrives,
view-models will source their data from the backend client rather than samples.
"""

from __future__ import annotations

from PySide6.QtCore import QObject


class ViewModel(QObject):
    """Base class for presentation view-models."""

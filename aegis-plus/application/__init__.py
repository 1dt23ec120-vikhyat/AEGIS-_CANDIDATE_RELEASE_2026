"""Application composition root.

Assembles AEGIS+ from its layers: configuration, logging, persistence, the
embedded backend, and lifecycle orchestration. This package is the only place
that wires concrete implementations to Core ports.
"""

from application.app import Application
from application.bootstrap import bootstrap

__all__ = ["Application", "bootstrap"]

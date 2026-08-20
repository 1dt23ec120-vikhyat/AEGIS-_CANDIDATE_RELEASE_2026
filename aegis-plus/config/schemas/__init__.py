"""Configuration section schemas.

Each module defines the Pydantic model for one configuration domain. The root
``Settings`` aggregate (in ``config.settings``) composes these sections.
"""

from config.schemas.ai import AISettings
from config.schemas.application import ApplicationSettings, BackendSettings
from config.schemas.copilot import CopilotSettings
from config.schemas.database import DatabaseSettings
from config.schemas.gmail import GmailSettings
from config.schemas.logging import LoggingSettings
from config.schemas.security import SecuritySettings
from config.schemas.ui import UISettings

__all__ = [
    "AISettings",
    "ApplicationSettings",
    "BackendSettings",
    "CopilotSettings",
    "DatabaseSettings",
    "GmailSettings",
    "LoggingSettings",
    "SecuritySettings",
    "UISettings",
]

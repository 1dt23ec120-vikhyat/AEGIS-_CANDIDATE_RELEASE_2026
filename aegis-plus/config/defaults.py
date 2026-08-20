"""Secure default values for the configuration subsystem.

Centralizing defaults here keeps the schema modules declarative and provides a
single place to review the platform's out-of-the-box posture. Defaults are
chosen to be safe: local-only networking, informational logging, and an
explicitly insecure secret sentinel that production validation rejects.
"""

from __future__ import annotations

from typing import Final

# --- Application ---------------------------------------------------------
DEFAULT_APP_NAME: Final[str] = "AEGIS+"
DEFAULT_APP_VERSION: Final[str] = "0.1.0"
DEFAULT_ENVIRONMENT: Final[str] = "development"
DEFAULT_DEBUG: Final[bool] = True

# --- Embedded backend (decision #1: FastAPI over localhost) --------------
# Bind to loopback by default so the backend is never exposed off-host.
DEFAULT_BACKEND_HOST: Final[str] = "127.0.0.1"
DEFAULT_BACKEND_PORT: Final[int] = 8137
MIN_TCP_PORT: Final[int] = 1
MAX_TCP_PORT: Final[int] = 65535

# --- Database (SQLite for v1.0; PostgreSQL-ready) ------------------------
DEFAULT_DATABASE_URL: Final[str] = "sqlite:///database/sqlite/aegis.db"
DEFAULT_DATABASE_ECHO: Final[bool] = False

# --- Logging -------------------------------------------------------------
DEFAULT_LOG_LEVEL: Final[str] = "INFO"
DEFAULT_LOG_DIR: Final[str] = "logs"
DEFAULT_LOG_ROTATION: Final[str] = "10 MB"
DEFAULT_LOG_RETENTION_DAYS: Final[int] = 14
VALID_LOG_LEVELS: Final[tuple[str, ...]] = (
    "TRACE",
    "DEBUG",
    "INFO",
    "SUCCESS",
    "WARNING",
    "ERROR",
    "CRITICAL",
)

# --- Security ------------------------------------------------------------
# Sentinel marking an unconfigured secret. Production validation rejects it.
INSECURE_SECRET_SENTINEL: Final[str] = "change-me-in-your-local-env"
MIN_SECRET_KEY_LENGTH: Final[int] = 32
DEFAULT_SESSION_TIMEOUT_MINUTES: Final[int] = 30

# --- User interface ------------------------------------------------------
DEFAULT_THEME: Final[str] = "dark"
VALID_THEMES: Final[tuple[str, ...]] = ("dark", "light", "enterprise")
DEFAULT_LANGUAGE: Final[str] = "en"

# --- AI subsystem --------------------------------------------------------
DEFAULT_MODELS_DIR: Final[str] = "models"
DEFAULT_MODEL_REGISTRY_FILE: Final[str] = "models/registry.json"

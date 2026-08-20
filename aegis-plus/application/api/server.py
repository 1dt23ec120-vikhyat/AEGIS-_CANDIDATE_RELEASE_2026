"""Embedded backend server.

Runs the FastAPI application under uvicorn in a dedicated background thread so
the desktop UI (which owns the main thread) is never blocked. Exposes a
:class:`BackgroundService` interface so the lifecycle manages it uniformly.
"""

from __future__ import annotations

import threading
import time

import uvicorn
from fastapi import FastAPI

from application.background import BackgroundService
from core.interfaces import ILogger

_START_TIMEOUT_SECONDS = 10.0
_STOP_TIMEOUT_SECONDS = 10.0
_POLL_INTERVAL_SECONDS = 0.02


class _ThreadedServer(uvicorn.Server):
    """A uvicorn server that installs no OS signal handlers.

    Signal handlers can only be registered on the main thread; this server runs
    on a worker thread, so handler installation is suppressed.
    """

    def install_signal_handlers(self) -> None:
        """Override to install no signal handlers."""
        return


class BackendServer(BackgroundService):
    """Serves the FastAPI application in a background thread."""

    def __init__(
        self,
        app: FastAPI,
        *,
        host: str,
        port: int,
        logger: ILogger,
    ) -> None:
        """Initialize the server.

        Args:
            app: The FastAPI application to serve.
            host: Bind host (loopback by default via configuration).
            port: Bind port.
            logger: Injected logger.
        """
        self._host = host
        self._port = port
        self._logger = logger
        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        self._server = _ThreadedServer(config)
        self._thread: threading.Thread | None = None

    @property
    def name(self) -> str:
        """The service name."""
        return "backend-server"

    @property
    def base_url(self) -> str:
        """The base URL the UI uses to reach the backend."""
        return f"http://{self._host}:{self._port}"

    @property
    def is_running(self) -> bool:
        """Whether the server thread is alive and the server has started."""
        return self._thread is not None and self._thread.is_alive() and self._server.started

    def start(self) -> None:
        """Start the server thread and wait until it is accepting requests.

        Raises:
            RuntimeError: If the server does not start within the timeout.
        """
        if self.is_running:
            return
        self._thread = threading.Thread(target=self._server.run, name="aegis-backend", daemon=True)
        self._thread.start()

        deadline = time.monotonic() + _START_TIMEOUT_SECONDS
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("Backend server failed to start within timeout")
            time.sleep(_POLL_INTERVAL_SECONDS)
        self._logger.info("Backend server listening on {}", self.base_url)

    def stop(self) -> None:
        """Signal the server to exit and wait for the thread to finish."""
        if self._thread is None:
            return
        self._server.should_exit = True
        self._thread.join(timeout=_STOP_TIMEOUT_SECONDS)
        self._thread = None
        self._logger.info("Backend server stopped")

"""AEGIS+ entry point.

Assembles and runs the application end to end: bootstraps the composition root,
starts the backend lifecycle (configure logging, apply migrations, verify the
database, start the embedded backend, record the first audit event), then
launches the desktop UI pointed at the backend. When the UI closes, the lifecycle
is shut down cleanly.

This root script is the one place that composes the application layer with the
UI layer, keeping the composition root itself free of any UI framework.
"""

from __future__ import annotations

import sys

from application import bootstrap
from ui import run_desktop


def main(argv: list[str] | None = None) -> int:
    """Run AEGIS+.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv``).

    Returns:
        The process exit code.
    """
    application = bootstrap()
    application.start()
    settings = application.container.settings
    try:
        return run_desktop(
            application.backend_url,
            argv=argv if argv is not None else sys.argv,
            environment=settings.application.environment.value,
            version=settings.application.version,
        )
    finally:
        application.stop()


if __name__ == "__main__":
    raise SystemExit(main())

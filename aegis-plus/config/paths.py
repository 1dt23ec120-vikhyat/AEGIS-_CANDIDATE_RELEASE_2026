"""Project filesystem paths.

Provides a single source of truth for the repository's directory layout so that
no module hardcodes paths (a Folder Structure requirement). All paths derive
from the repository root, which is resolved relative to this file's location.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# This file lives at ``<repo_root>/config/paths.py``; the repository root is the
# parent of the ``config`` package directory.
_REPO_ROOT: Path = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class ProjectPaths:
    """Immutable collection of resolved project paths.

    Attributes:
        root: Repository root directory.
        config_dir: Directory containing YAML configuration files.
        logs_dir: Directory for log files.
        database_dir: Directory for database resources.
        sqlite_dir: Directory for local SQLite database files.
        models_dir: Directory for AI model artifacts.
        reports_dir: Directory for generated reports.
        resources_dir: Directory for static resources.
        env_file: Path to the local ``.env`` file (may not exist).
    """

    root: Path
    config_dir: Path
    logs_dir: Path
    database_dir: Path
    sqlite_dir: Path
    models_dir: Path
    reports_dir: Path
    resources_dir: Path
    env_file: Path

    @classmethod
    def create(cls, root: Path | None = None) -> ProjectPaths:
        """Build a :class:`ProjectPaths` rooted at ``root``.

        Args:
            root: Optional explicit repository root. Defaults to the resolved
                repository root. Primarily overridden in tests.

        Returns:
            A fully resolved, immutable :class:`ProjectPaths`.
        """
        base = (root or _REPO_ROOT).resolve()
        return cls(
            root=base,
            config_dir=base / "config",
            logs_dir=base / "logs",
            database_dir=base / "database",
            sqlite_dir=base / "database" / "sqlite",
            models_dir=base / "models",
            reports_dir=base / "reports",
            resources_dir=base / "resources",
            env_file=base / ".env",
        )

    def resolve(self, path: str | Path) -> Path:
        """Resolve a possibly-relative path against the repository root.

        Absolute paths are returned unchanged; relative paths are anchored to
        the repository root so behaviour is independent of the process's
        current working directory.

        Args:
            path: An absolute or root-relative path.

        Returns:
            An absolute, resolved path.
        """
        candidate = Path(path)
        if candidate.is_absolute():
            return candidate.resolve()
        return (self.root / candidate).resolve()

    def config_file(self, name: str) -> Path:
        """Return the path to a named YAML file in the config directory.

        Args:
            name: File name (e.g. ``"database.yaml"``).

        Returns:
            The absolute path to the configuration file.
        """
        return self.config_dir / name

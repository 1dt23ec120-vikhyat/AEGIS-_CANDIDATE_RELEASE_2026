"""LightGBM model loader.

Infrastructure adapter that loads a LightGBM booster from disk. Model I/O lives
here, not in the AI layer: the analyzer receives an already-loaded model, so it
stays free of file access. A missing or unreadable model yields ``None`` so the
analyzer can fall back gracefully.

**Note:** the current bundled model (``url_lightgbm.txt``) is a demonstration
artifact trained on synthetic data. When a production model trained on a real
labelled dataset is available, it replaces the file at the same path — no loader
or architecture changes required.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.interfaces import ILogger


class LightGbmModelLoader:
    """Loads a LightGBM booster from a model file."""

    def __init__(self, model_path: Path, logger: ILogger) -> None:
        """Initialize the loader.

        Args:
            model_path: Path to the LightGBM booster text model.
            logger: Injected logger.
        """
        self._model_path = model_path
        self._logger = logger

    def load(self) -> Any:
        """Return the loaded booster, or ``None`` if unavailable."""
        if not self._model_path.exists():
            self._logger.warning(
                "URL model not found at {}; using heuristic fallback",
                self._model_path,
            )
            return None
        try:
            import lightgbm as lgb

            booster = lgb.Booster(model_file=str(self._model_path))
            self._logger.info("Loaded URL model from {}", self._model_path)
            return booster
        except Exception as exc:  # broad: any load failure -> graceful fallback
            self._logger.error("Failed to load URL model: {}", exc)
            return None

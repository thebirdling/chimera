"""
chimera.engine.normalizer — Score normalization pipeline.

Maps raw anomaly scores from heterogeneous detectors into a common [0, 1]
interval. Supports MinMax and quantile-based projections with explicit
safeguards for degenerate score distributions.

Design rationale
----------------
Raw scores from Isolation Forest (ranges from -1 to +1, inverted) and LOF
(unbounded positive) are mathematically incompatible. Naive combination
produces misleading ensemble signals. This module fits a per-model
normalization transform on the training distribution and applies it
consistently at inference time.
"""
from __future__ import annotations

import logging
import json
from pathlib import Path
from typing import Literal

import numpy as np

from chimera.engine.exceptions import InsufficientDataError  # noqa: F401 (re-exported)

logger = logging.getLogger(__name__)

NormStrategy = Literal["minmax", "quantile"]


class ScoreNormalizer:
    """Per-model normalization pipeline.

    Maps raw detector scores → [0, 1] with the following guarantees:

    1. **Score collapse**: if ``max - min < collapse_epsilon``, all outputs are
       set to 0.5 and a WARNING is emitted. (Avoids divide-by-zero.)
    2. **Low variance**: if ``std < low_variance_threshold``, automatically
       switches to quantile normalization for stability.
    3. **Insufficient samples**: raises :class:`InsufficientDataError` if
       fewer than ``MIN_SAMPLES`` are provided (prevents spurious fits).

    Parameters
    ----------
    strategy:
        ``"minmax"`` projects scores linearly based on training min/max.
        ``"quantile"`` uses the ``quantile_range`` percentiles, yielding more
        robustness to outliers in the training set itself.
    low_variance_threshold:
        If ``scores.std()`` is below this value, quantile projection is used
        regardless of ``strategy``.
    collapse_epsilon:
        Minimum acceptable score range. Below this, output is constant 0.5.
    quantile_range:
        ``(q_lo, q_hi)`` as fractions (e.g. ``(0.05, 0.95)``).
    """

    MIN_SAMPLES: int = 30

    def __init__(
        self,
        strategy: NormStrategy = "minmax",
        low_variance_threshold: float = 1e-4,
        collapse_epsilon: float = 1e-6,
        quantile_range: tuple[float, float] = (0.05, 0.95),
    ) -> None:
        self.strategy = strategy
        self.low_variance_threshold = low_variance_threshold
        self.collapse_epsilon = collapse_epsilon
        self.quantile_range = quantile_range
        self._params: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fit(self, model_id: str, raw_scores: np.ndarray) -> None:
        """Fit normalization parameters for ``model_id`` from training scores.

        Parameters
        ----------
        model_id:
            Unique identifier for this detector (e.g. ``"isolation_forest"``).
        raw_scores:
            1-D array of raw anomaly scores from training.

        Raises
        ------
        InsufficientDataError
            If ``len(raw_scores) < MIN_SAMPLES``.
        """
        scores = np.asarray(raw_scores, dtype=np.float64).ravel()

        if len(scores) < self.MIN_SAMPLES:
            raise InsufficientDataError(
                f"ScoreNormalizer.fit() requires >= {self.MIN_SAMPLES} samples; "
                f"got {len(scores)} for model '{model_id}'."
            )

        score_range = float(scores.max() - scores.min())
        score_std = float(scores.std())

        # Guard 1: score collapse
        if score_range < self.collapse_epsilon:
            # Identity research channels already emit bounded heuristic scores
            # in [0, 1]. Preserve them so low-variance historical windows do
            # not erase useful test-time separation.
            if model_id.startswith("identity_") and scores.min() >= 0.0 and scores.max() <= 1.0:
                logger.warning(
                    "[normalizer] Low-range bounded research scores for '%s'. "
                    "Using passthrough normalization instead of constant 0.5.",
                    model_id,
                )
                self._params[model_id] = {"mode": "passthrough"}
                return
            logger.warning(
                "[normalizer] Score collapse for '%s': range=%.2e < epsilon=%.2e. "
                "Normalization will output constant 0.5.",
                model_id, score_range, self.collapse_epsilon,
            )
            self._params[model_id] = {"mode": "constant"}
            return

        # Guard 2: low variance → force quantile
        effective_strategy = self.strategy
        if score_std < self.low_variance_threshold:
            logger.warning(
                "[normalizer] Low variance for '%s': std=%.2e < threshold=%.2e. "
                "Switching to quantile normalization.",
                model_id, score_std, self.low_variance_threshold,
            )
            effective_strategy = "quantile"

        if effective_strategy == "minmax":
            self._params[model_id] = {
                "mode": "minmax",
                "min": float(scores.min()),
                "max": float(scores.max()),
            }
        else:  # quantile
            q_lo_pct = self.quantile_range[0] * 100.0
            q_hi_pct = self.quantile_range[1] * 100.0
            q_lo, q_hi = np.percentile(scores, [q_lo_pct, q_hi_pct])
            self._params[model_id] = {
                "mode": "quantile",
                "q_lo": float(q_lo),
                "q_hi": float(q_hi),
            }

        logger.debug(
            "[normalizer] Fitted '%s': strategy=%s, params=%s",
            model_id, effective_strategy, self._params[model_id],
        )

    def transform(self, model_id: str, raw_scores: np.ndarray) -> np.ndarray:
        """Normalize raw scores for ``model_id`` to [0, 1].

        Parameters
        ----------
        model_id:
            Must have been previously fitted via :meth:`fit`.
        raw_scores:
            1-D array of raw anomaly scores to normalize.

        Returns
        -------
        np.ndarray
            Scores projected to [0, 1], clipped to that range.
        """
        if model_id not in self._params:
            raise KeyError(
                f"No fitted parameters for '{model_id}'. Call fit() first."
            )

        scores = np.asarray(raw_scores, dtype=np.float64).ravel()
        params = self._params[model_id]

        if params["mode"] == "constant":
            return np.full(len(scores), 0.5, dtype=np.float64)

        if params["mode"] == "passthrough":
            return np.clip(scores, 0.0, 1.0)

        if params["mode"] == "minmax":
            lo, hi = params["min"], params["max"]
            span = max(hi - lo, self.collapse_epsilon)
            normalized = (scores - lo) / span
        else:  # quantile
            lo, hi = params["q_lo"], params["q_hi"]
            span = max(hi - lo, self.collapse_epsilon)
            normalized = (scores - lo) / span

        return np.clip(normalized, 0.0, 1.0)

    def fit_transform(self, model_id: str, raw_scores: np.ndarray) -> np.ndarray:
        """Convenience method: fit then transform in one call."""
        self.fit(model_id, raw_scores)
        return self.transform(model_id, raw_scores)

    def is_fitted(self, model_id: str) -> bool:
        """Return True if normalization parameters exist for ``model_id``."""
        return model_id in self._params

    def fitted_models(self) -> list[str]:
        """Return list of model IDs with fitted parameters."""
        return list(self._params.keys())

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Persist fitted parameters to disk (JSON — Twin Sync redundancy)."""
        from chimera.engine.safe_io import atomic_sync_write_text
        path = Path(path)
        data = {
            "version": "0.4",
            "strategy": self.strategy,
            "low_variance_threshold": self.low_variance_threshold,
            "collapse_epsilon": self.collapse_epsilon,
            "quantile_range": list(self.quantile_range),
            "params": {
                model_id: {k: v for k, v in p.items()}
                for model_id, p in self._params.items()
            },
        }
        # A1: Always save with redundancy mirror
        atomic_sync_write_text(path, json.dumps(data, indent=2), mode=0o640)
        logger.debug("[normalizer] Saved to %s (and .bak mirror)", path)

    @classmethod
    def load(cls, path: str | Path) -> "ScoreNormalizer":
        """Load from disk (JSON) with automatic FAIL-SAFE redundancy fallback."""
        from chimera.engine.safe_io import load_with_fallback
        path = Path(path)
        bak_path = path.with_suffix(path.suffix + ".bak")

        # A1: Load with redundancy mirror fallback
        # First, try to load primary directly to detect content errors (corruption)
        try:
            if not path.exists():
                raise FileNotFoundError()
            bytes_data = path.read_bytes()
            data = json.loads(bytes_data.decode("utf-8"))
        except (Exception, FileNotFoundError) as e:
            if bak_path.exists():
                logger.critical(
                    "[normalizer] PRIMARY STATE CORRUPT or missing (%s): %s. "
                    "Engaging FAIL-SAFE REDUNDANCY: loading from backup.",
                    type(e).__name__, path.name
                )
                bytes_data = load_with_fallback(path, force_backup=True)
                data = json.loads(bytes_data.decode("utf-8"))
            else:
                raise

        inst = cls(
            strategy=data["strategy"],
            low_variance_threshold=data["low_variance_threshold"],
            collapse_epsilon=data["collapse_epsilon"],
            quantile_range=tuple(data["quantile_range"]),
        )
        raw_params = data["params"]
        # C2: Plausibility bounds check — reject degenerate/zeroed params
        cls._validate_params_plausibility(raw_params, path)
        inst._params = raw_params
        logger.debug("[normalizer] Loaded from %s", path)
        return inst

    @staticmethod
    def _validate_params_plausibility(params: dict, path: "Path") -> None:
        """C2: Reject normalizer params that look zeroed or degenerate.

        Defends against model-parameter manipulation: an attacker who can write
        the normalizer JSON could set all mins/maxes to the same value, forcing
        all normalized scores to 0.5 (making everything look normal) or to 0/1
        (making everything look maximally anomalous to flood the SOC).
        """
        from chimera.engine.exceptions import IntegrityError
        for model_id, p in params.items():
            # Support both minmax (min/max) and quantile (q_lo/q_hi)
            lo = p.get("min", p.get("q_lo", 0.0))
            hi = p.get("max", p.get("q_hi", 0.0))

            effective_range = hi - lo

            # All-zero params: sign of file zeroing/tampering
            if hi == 0.0 and lo == 0.0:
                raise IntegrityError(
                    f"[normalizer] Plausibility check FAILED for '{model_id}' "
                    f"in {path}: all-zero params (lo=0, hi=0). "
                    "Possible parameter zeroing attack. Will not load."
                )

            # Single-point params: both extremes identical to machine precision
            if effective_range < 1e-12:
                raise IntegrityError(
                    f"[normalizer] Plausibility check FAILED for '{model_id}' "
                    f"in {path}: degenerate range (lo={lo}, hi={hi}). "
                    "All inputs would normalize to the same value. "
                    "Possible score-fixation attack. Will not load."
                )

    def __repr__(self) -> str:
        return (
            f"ScoreNormalizer(strategy={self.strategy!r}, "
            f"fitted_models={self.fitted_models()})"
        )

"""
chimera.engine.threshold — Dynamic threshold engine.

Implements contamination-based percentile thresholding with drift tracking.
Threshold instability is exposed as a first-class robustness metric.

Core formula
------------
    τ_t = percentile(S, 100 × (1 − contamination))
    Δτ  = |τ_t − τ_{t-1}|

Where S is the ensemble score distribution over the current evaluation window.

Threshold drift Δτ
------------------
A high value of Δτ indicates that the ensemble score distribution is shifting
rapidly — either because the underlying user behavior is changing, because the
model is poorly calibrated for this data, or because an adversary is injecting
events designed to push the threshold. Monitoring Δτ is the primary robustness
diagnostic for long-running Chimera deployments.

Instability metric
------------------
    instability = mean(|Δτ_1|, |Δτ_2|, ..., |Δτ_t|)

Values near 0 indicate a stable, well-calibrated threshold.
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


from chimera.engine.exceptions import InsufficientDataError, NotFittedError  # noqa: F401


class DynamicThreshold:
    """Contamination-percentile thresholding with drift tracking.

    Parameters
    ----------
    contamination:
        Expected fraction of anomalies in the data. Must be in (0, 0.5).
        The threshold is set at the ``(1 - contamination)``-th percentile
        of the ensemble score distribution.
    recalc_window:
        Number of events between threshold recalculations in streaming mode.
    max_drift_history:
        Maximum number of Δτ values stored in drift history. Older entries
        are discarded (ring-buffer behaviour via ``collections.deque``).
    """

    def __init__(
        self,
        contamination: float = 0.05,
        recalc_window: int = 500,
        max_drift_history: int = 5000,
    ) -> None:
        if not (0 < contamination < 0.5):
            raise ValueError(
                f"contamination must be in (0, 0.5); got {contamination}."
            )

        self.contamination = contamination
        self.recalc_window = recalc_window

        self._drift_history: deque[float] = deque(maxlen=max_drift_history)
        self._tau: Optional[float] = None
        self._update_count: int = 0

    # ------------------------------------------------------------------
    # Core threshold operations
    # ------------------------------------------------------------------

    MIN_FIT_SAMPLES: int = 10

    def fit(self, scores: np.ndarray) -> float:
        """Compute τ_0 from training scores.

        Parameters
        ----------
        scores:
            1-D array of ensemble scores from the training set.

        Returns
        -------
        float
            The fitted threshold τ_0.

        Raises
        ------
        InsufficientDataError
            If fewer than ``MIN_FIT_SAMPLES`` scores are provided.
        """
        scores = np.asarray(scores, dtype=np.float64).ravel()
        if len(scores) < self.MIN_FIT_SAMPLES:
            raise InsufficientDataError(
                f"DynamicThreshold.fit() requires >= {self.MIN_FIT_SAMPLES} samples; "
                f"got {len(scores)}."
            )
        self._tau = self._percentile(scores)
        logger.info(
            "[threshold] tau_0=%.6f  (contamination=%.3f, n=%d)",
            self._tau, self.contamination, len(scores),
        )
        return self._tau

    def update(self, new_scores: np.ndarray) -> tuple[float, float]:
        """Recalculate τ from a new score window and compute drift Δτ.

        Call this every ``recalc_window`` events in streaming mode.

        Parameters
        ----------
        new_scores:
            Most recent window of ensemble scores.

        Returns
        -------
        tuple[float, float]
            ``(tau_t, delta_tau)`` — new threshold and absolute drift.

        Raises
        ------
        RuntimeError
            If :meth:`fit` has not been called first.
        """
        if self._tau is None:
            raise NotFittedError("Call fit() before update().")

        new_scores = np.asarray(new_scores, dtype=np.float64).ravel()
        prev_tau = self._tau
        new_tau = self._percentile(new_scores)
        delta_tau = abs(new_tau - prev_tau)

        self._tau = new_tau
        self._drift_history.append(delta_tau)
        self._update_count += 1

        logger.info(
            "[threshold] update #%d: %.6f → %.6f  Δτ=%.6f  "
            "instability=%.6f",
            self._update_count, prev_tau, new_tau,
            delta_tau, self.instability_metric,
        )
        return new_tau, delta_tau

    def predict(self, scores: np.ndarray) -> np.ndarray:
        """Return boolean anomaly mask: True where score >= current threshold.

        Parameters
        ----------
        scores:
            1-D array of ensemble scores.

        Returns
        -------
        np.ndarray[bool]
            Anomaly flags.
        """
        if self._tau is None:
            raise NotFittedError("Call fit() before predict().")
        return np.asarray(scores, dtype=np.float64) >= self._tau

    # ------------------------------------------------------------------
    # Diagnostic properties
    # ------------------------------------------------------------------

    @property
    def current_threshold(self) -> Optional[float]:
        """Current threshold value τ_t. None if fit() has not been called."""
        return self._tau

    @property
    def drift_history(self) -> list[float]:
        """Full history of Δτ values (most recent ``max_drift_history`` entries)."""
        return list(self._drift_history)

    @property
    def instability_metric(self) -> float:
        """Mean absolute drift Σ|Δτ| / n.

        Primary robustness KPI.
        - Near 0: threshold is stable.
        - Large values: threshold is drifting, indicating distribution shift
          or poor calibration.
        """
        if not self._drift_history:
            return 0.0
        return float(np.mean(list(self._drift_history)))

    @property
    def update_count(self) -> int:
        """Number of threshold updates performed via :meth:`update`."""
        return self._update_count

    def sensitivity_at_contamination(
        self,
        scores: np.ndarray,
        contamination_range: tuple[float, float] = (0.01, 0.30),
        n_steps: int = 20,
    ) -> list[tuple[float, float]]:
        """Compute threshold τ across a contamination sweep.

        Returns a sensitivity curve: list of ``(contamination, tau)`` pairs.
        Useful for understanding how the threshold responds to different
        assumptions about the fraction of anomalies in the data.

        Parameters
        ----------
        scores:
            Ensemble score distribution to evaluate against.
        contamination_range:
            ``(min_contamination, max_contamination)`` to sweep.
        n_steps:
            Number of evenly-spaced contamination values to evaluate.
        """
        scores = np.asarray(scores, dtype=np.float64).ravel()
        lo, hi = contamination_range
        contamination_values = np.linspace(lo, hi, n_steps)

        curve: list[tuple[float, float]] = []
        for c in contamination_values:
            pct = 100.0 * (1.0 - float(c))
            tau = float(np.percentile(scores, pct))
            curve.append((float(c), tau))
        return curve

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _percentile(self, scores: np.ndarray) -> float:
        pct = 100.0 * (1.0 - self.contamination)
        return float(np.percentile(scores, pct))

    def __repr__(self) -> str:
        return (
            f"DynamicThreshold(contamination={self.contamination}, "
            f"tau={self._tau}, updates={self._update_count}, "
            f"instability={self.instability_metric:.4f})"
        )

"""
chimera.engine.voter — Ensemble voting engine.

Combines normalized per-model scores into a single ensemble score S(X_t)
using configurable voting strategies. Also computes inter-model disagreement
entropy and score variance as robustness diagnostics.

Voting strategies
-----------------
mean          — Simple arithmetic mean. Baseline.
median        — Robust to a single outlier model.
trimmed_mean  — Drops the top and bottom k% of model scores per sample,
                then averages. Most robust under adversarial detector noise.
weighted      — Weighted average using per-model confidence weights.

Disagreement entropy
--------------------
H(X_t) = -Σ p_i log(p_i) where p_i are softmax-normalized per-model scores.

High H → models disagree about whether X_t is anomalous. This is a critical
robustness signal: a high-scoring event with high H should be flagged as
"uncertain" even if the ensemble score clears the threshold.
"""
from __future__ import annotations

import logging
from typing import Literal, Optional

import numpy as np

logger = logging.getLogger(__name__)

VotingStrategy = Literal["mean", "median", "trimmed_mean", "weighted"]

_SOFTMAX_TEMP = 1.0  # temperature for softmax in entropy calculation
_LOG_EPSILON = 1e-12  # prevent log(0)
_SCORE_EPSILON = 1e-9  # prevent all-zero distributions


class EnsembleVoter:
    """Combines normalized scores from k detectors into one ensemble score.

    Parameters
    ----------
    strategy:
        Voting strategy. See module docstring.
    trim_fraction:
        Fraction of extreme models to trim per sample (for ``"trimmed_mean"``).
        E.g. 0.1 removes the top 10% and bottom 10% of model scores.
    weights:
        Dict mapping ``model_id`` → weight (for ``"weighted"`` strategy).
        Missing model IDs default to weight 1.0.
    """

    def __init__(
        self,
        strategy: VotingStrategy = "mean",
        trim_fraction: float = 0.1,
        weights: Optional[dict[str, float]] = None,
    ) -> None:
        _VALID = {"mean", "median", "trimmed_mean", "weighted"}
        if strategy not in _VALID:
            raise ValueError(
                f"Unknown voting strategy {strategy!r}. Choose from: {sorted(_VALID)}"
            )
        self.strategy = strategy
        self.trim_fraction = trim_fraction
        self.weights: dict[str, float] = weights or {}

    # ------------------------------------------------------------------
    # Primary voting
    # ------------------------------------------------------------------

    def vote(self, scores: dict[str, np.ndarray]) -> np.ndarray:
        """Compute ensemble score S(X_t) from normalized per-model scores.

        Parameters
        ----------
        scores:
            Mapping of ``model_id`` → 1-D array of normalized scores in [0, 1].
            All arrays must have the same length.

        Returns
        -------
        np.ndarray
            1-D ensemble score array, same length as inputs.

        Raises
        ------
        ValueError
            If ``scores`` is empty or arrays have mismatched lengths.
        """
        if not scores:
            raise ValueError("EnsembleVoter.vote(): scores dict is empty.")

        model_ids = list(scores.keys())
        self._validate_shapes(scores)
        score_matrix = np.stack(
            [np.asarray(scores[m], dtype=np.float64) for m in model_ids], axis=0
        )  # shape: (k, n)

        if self.strategy == "mean":
            return score_matrix.mean(axis=0)

        elif self.strategy == "median":
            return np.median(score_matrix, axis=0)

        elif self.strategy == "trimmed_mean":
            return self._trimmed_mean(score_matrix)

        elif self.strategy == "weighted":
            return self._weighted_mean(model_ids, score_matrix)

        else:
            raise ValueError(
                f"Unknown voting strategy {self.strategy!r}. "
                "Choose from: mean, median, trimmed_mean, weighted."
            )

    # ------------------------------------------------------------------
    # Robustness diagnostics
    # ------------------------------------------------------------------

    def disagreement_entropy(self, scores: dict[str, np.ndarray]) -> np.ndarray:
        """Per-sample inter-model disagreement (Jensen-Shannon Divergence).

        Measures how much the per-model score distributions diverge from their
        mixture. JSD is symmetric, bounded in ``[0, log(k)]``, and zero iff
        all models produce identical scores.

        **Why not softmax entropy?**
        The previous implementation used softmax-normalized scores as a
        probability distribution. This measured which model had the *highest*
        score, not whether models *agreed*. Two models scoring ``[0.98, 0.97]``
        (strong agreement) produced near-maximum entropy — the exact opposite of
        the intended semantics. JSD corrects this.

        Parameters
        ----------
        scores:
            Same format as :meth:`vote`.

        Returns
        -------
        np.ndarray
            1-D JSD array ∈ [0, log(k)] per sample. Larger = more disagreement.
        """
        if not scores or len(scores) < 2:
            return np.zeros(
                len(next(iter(scores.values()))) if scores else 0, dtype=np.float64
            )

        self._validate_shapes(scores)
        # (k, n): each row is one model's score vector
        score_matrix = np.stack(
            [np.asarray(s, dtype=np.float64) for s in scores.values()], axis=0
        )
        k = score_matrix.shape[0]

        # Normalize each model's scores to a probability distribution (per-sample axis).
        # Add epsilon before normalizing to avoid divide-by-zero on all-zero rows.
        score_matrix = score_matrix + _SCORE_EPSILON
        # Normalize across models per sample: (k, n) → treat column as distribution
        col_sums = score_matrix.sum(axis=0, keepdims=True)  # (1, n)
        # Guard: if col_sum is still effectively zero (degenerate), set to uniform
        col_sums = np.where(col_sums < 1e-15, 1.0, col_sums)
        p_matrix = score_matrix / col_sums  # (k, n)

        # Mixture distribution M = mean over models
        M = p_matrix.mean(axis=0, keepdims=True)  # (1, n)

        # JSD = (1/k) * Σ_i KL(p_i ∥ M), where KL(p∥q) = Σ p log(p/q)
        # Clip arguments to log to avoid log(0) → -inf → nan
        safe_p = np.clip(p_matrix, 1e-15, None)
        safe_M = np.clip(M, 1e-15, None)
        log_ratio = np.log(safe_p) - np.log(safe_M)
        kl_per_model = (p_matrix * log_ratio).sum(axis=0)  # (n,) sum of KL per sample
        jsd = kl_per_model / k
        # JSD is non-negative by construction; clamp floating-point noise and NaN
        jsd = np.where(np.isfinite(jsd), jsd, 0.0)
        return np.maximum(jsd, 0.0)

    def disagreement_entropy_legacy(self, scores: dict[str, np.ndarray]) -> np.ndarray:
        """Deprecated: softmax-entropy disagreement metric.

        .. deprecated::
            This method measured softmax concentration (which model had the
            *highest* absolute score), not inter-model disagreement.
            Use :meth:`disagreement_entropy` (JSD) instead.
        """
        import warnings
        warnings.warn(
            "disagreement_entropy_legacy is deprecated and measures softmax "
            "concentration, not disagreement. Use disagreement_entropy (JSD).",
            DeprecationWarning,
            stacklevel=2,
        )
        if not scores:
            return np.array([], dtype=np.float64)
        self._validate_shapes(scores)
        score_matrix = np.stack(
            [np.asarray(s, dtype=np.float64) + _SCORE_EPSILON for s in scores.values()],
            axis=0,
        )
        shifted = score_matrix - score_matrix.max(axis=0, keepdims=True)
        exp_scores = np.exp(shifted / _SOFTMAX_TEMP)
        p_matrix = exp_scores / exp_scores.sum(axis=0, keepdims=True)
        entropy = -(p_matrix * np.log(p_matrix + _LOG_EPSILON)).sum(axis=0)
        return entropy


    def score_variance(self, scores: dict[str, np.ndarray]) -> np.ndarray:
        """Per-sample variance across model scores.

        High variance = models produce wildly different anomaly estimates
        for the same event. Complements entropy as a uncertainty metric.

        Returns
        -------
        np.ndarray
            1-D variance array, same length as input arrays.
        """
        if not scores:
            return np.array([], dtype=np.float64)

        self._validate_shapes(scores)
        score_matrix = np.stack(
            [np.asarray(s, dtype=np.float64) for s in scores.values()], axis=0
        )
        return score_matrix.var(axis=0)

    def max_disagreement_entropy(self, k: int) -> float:
        """Theoretical maximum entropy for k models (uniform distribution).

        Useful for normalizing entropy to [0, 1] across different ensemble sizes.
        """
        if k <= 1:
            return 0.0
        return float(np.log(k))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _trimmed_mean(self, score_matrix: np.ndarray) -> np.ndarray:
        """Per-sample trimmed mean: remove top and bottom trim_fraction of models."""
        k = score_matrix.shape[0]
        n_trim = max(1, int(round(k * self.trim_fraction)))

        if 2 * n_trim >= k:
            logger.warning(
                "[voter] trim_fraction=%.2f trims all %d models; "
                "falling back to mean.",
                self.trim_fraction, k,
            )
            return score_matrix.mean(axis=0)

        sorted_matrix = np.sort(score_matrix, axis=0)  # sort along model axis
        trimmed = sorted_matrix[n_trim : k - n_trim]
        return trimmed.mean(axis=0)

    def _weighted_mean(
        self, model_ids: list[str], score_matrix: np.ndarray
    ) -> np.ndarray:
        """Weighted average using self.weights (missing IDs default to 1.0)."""
        raw_weights = np.array(
            [self.weights.get(m, 1.0) for m in model_ids], dtype=np.float64
        )
        if raw_weights.sum() == 0:
            logger.warning("[voter] All weights are zero; falling back to mean.")
            return score_matrix.mean(axis=0)

        norm_weights = raw_weights / raw_weights.sum()
        return (norm_weights[:, np.newaxis] * score_matrix).sum(axis=0)

    @staticmethod
    def _validate_shapes(scores: dict[str, np.ndarray]) -> None:
        lengths = {k: len(v) for k, v in scores.items()}
        unique = set(lengths.values())
        if len(unique) > 1:
            raise ValueError(
                f"Score arrays have mismatched lengths: {lengths}. "
                "All arrays must have the same number of samples."
            )

    def __repr__(self) -> str:
        return (
            f"EnsembleVoter(strategy={self.strategy!r}, "
            f"trim_fraction={self.trim_fraction}, "
            f"n_weighted={len(self.weights)})"
        )

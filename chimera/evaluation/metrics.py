"""
chimera.evaluation.metrics — Robustness metrics for ensemble evaluation.

Implements the robustness-first evaluation framework described in the v0.3
design. Replaces traditional AUC-based evaluation with metrics that measure
how stable the detection engine is under distribution shift.

Core metrics
------------
threshold_drift_mean / max
    Mean and maximum |Δτ| over the evaluation period.
    Low values = stable threshold, good calibration.

disagreement_entropy_mean
    Mean inter-model disagreement entropy H(X_t).
    Low values = models agree = high confidence in ensemble output.

score_variance_mean
    Mean per-event variance across model scores.
    Low values = models are consistent signal sources.

sensitivity_curve
    List of (contamination, threshold) pairs showing how τ moves
    as the contamination assumption changes.

detection_rate_at_fpr
    When ground truth (injected event mask) is available:
    fraction of injected events detected at various FPR operating points.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class RobustnessReport:
    """Summary of all robustness metrics for a single evaluation run."""

    # Threshold stability
    threshold_drift_mean: float
    """Mean |Δτ| over all threshold updates. Primary stability KPI."""

    threshold_drift_max: float
    """Maximum |Δτ| observed. Flags worst-case instability."""

    threshold_drift_std: float
    """Standard deviation of |Δτ|."""

    # Inter-model agreement
    disagreement_entropy_mean: float
    """Mean Shannon entropy across model scores per event."""

    disagreement_entropy_std: float
    """Standard deviation of per-event entropy."""

    # Score distribution
    score_variance_mean: float
    """Mean per-event variance across model scores."""

    # Sensitivity
    sensitivity_curve: list[tuple[float, float]] = field(default_factory=list)
    """(contamination, tau) pairs over a contamination sweep."""

    # Detection performance (when ground truth available)
    detection_rate_at_fpr: dict[float, float] = field(default_factory=dict)
    """FPR → detection rate (fraction of injected events caught)."""

    false_positive_rate_observed: float = 0.0
    false_positive_count: int = 0
    true_positive_count: int = 0

    n_events: int = 0
    n_anomalies_flagged: int = 0
    n_injected: int = 0

    def summary(self) -> str:
        """Return a human-readable single-line summary."""
        dr = self.detection_rate_at_fpr
        dr_str = "  ".join(f"FPR={k:.2f}→DR={v:.2f}" for k, v in sorted(dr.items()))
        return (
            f"drift_mean={self.threshold_drift_mean:.4f}  "
            f"drift_max={self.threshold_drift_max:.4f}  "
            f"H_mean={self.disagreement_entropy_mean:.4f}  "
            f"var_mean={self.score_variance_mean:.4f}"
            + (f"  ({dr_str})" if dr_str else "")
        )

    def to_dict(self) -> dict:
        return {
            "threshold_drift_mean": self.threshold_drift_mean,
            "threshold_drift_max": self.threshold_drift_max,
            "threshold_drift_std": self.threshold_drift_std,
            "disagreement_entropy_mean": self.disagreement_entropy_mean,
            "disagreement_entropy_std": self.disagreement_entropy_std,
            "score_variance_mean": self.score_variance_mean,
            "sensitivity_curve": self.sensitivity_curve,
            "detection_rate_at_fpr": self.detection_rate_at_fpr,
            "false_positive_rate_observed": self.false_positive_rate_observed,
            "false_positive_count": self.false_positive_count,
            "true_positive_count": self.true_positive_count,
            "n_events": self.n_events,
            "n_anomalies_flagged": self.n_anomalies_flagged,
            "n_injected": self.n_injected,
        }


def compute_robustness(
    ensemble_scores: np.ndarray,
    per_model_scores: dict[str, np.ndarray],
    threshold_history: list[float],
    ground_truth_mask: Optional[np.ndarray] = None,
    contamination_range: tuple[float, float] = (0.01, 0.30),
    n_steps: int = 20,
    anomaly_mask: Optional[np.ndarray] = None,
) -> RobustnessReport:
    """Compute the full robustness report from evaluation run outputs.

    Parameters
    ----------
    ensemble_scores:
        1-D array of ensemble scores from the detection run.
    per_model_scores:
        Dict of ``model_id`` → 1-D score array (normalized, per-model).
    threshold_history:
        List of threshold values τ_0, τ_1, … from :class:`~chimera.engine.threshold.DynamicThreshold`.
    ground_truth_mask:
        Optional boolean array where True = injected (synthetic) event.
        Required for ``detection_rate_at_fpr``.
    contamination_range:
        ``(min_c, max_c)`` for sensitivity curve sweep.
    n_steps:
        Number of contamination values in the sweep.
    anomaly_mask:
        Boolean array of which events were flagged by the engine.
        Required for ``detection_rate_at_fpr``.

    Returns
    -------
    RobustnessReport
    """
    ensemble_scores = np.asarray(ensemble_scores, dtype=np.float64)

    # --- Threshold drift ---
    drifts = _compute_drifts(threshold_history)
    drift_mean = float(np.mean(drifts)) if drifts else 0.0
    drift_max = float(np.max(drifts)) if drifts else 0.0
    drift_std = float(np.std(drifts)) if drifts else 0.0

    # --- Disagreement entropy ---
    entropy = _disagreement_entropy(per_model_scores)
    H_mean = float(np.mean(entropy)) if len(entropy) else 0.0
    H_std = float(np.std(entropy)) if len(entropy) else 0.0

    # --- Score variance ---
    var_arr = _score_variance(per_model_scores)
    var_mean = float(np.mean(var_arr)) if len(var_arr) else 0.0

    # --- Sensitivity curve ---
    curve = sensitivity_curve(ensemble_scores, contamination_range, n_steps)

    # --- Detection rate at FPR (ground truth required) ---
    dr_at_fpr: dict[float, float] = {}
    n_flagged = 0
    n_injected = 0
    false_positive_count = 0
    false_positive_rate = 0.0
    true_positive_count = 0

    if ground_truth_mask is not None and anomaly_mask is not None:
        ground_truth_mask = np.asarray(ground_truth_mask, dtype=bool)
        anomaly_mask = np.asarray(anomaly_mask, dtype=bool)
        n_injected = int(ground_truth_mask.sum())
        n_flagged = int(anomaly_mask.sum())
        false_positive_count = int((anomaly_mask & ~ground_truth_mask).sum())
        true_positive_count = int((anomaly_mask & ground_truth_mask).sum())
        false_positive_rate = false_positive_count / max(int((~ground_truth_mask).sum()), 1)

        for target_fpr in [0.01, 0.05, 0.10, 0.20]:
            dr = _detection_rate_at_fpr(
                ensemble_scores, ground_truth_mask, target_fpr=target_fpr
            )
            dr_at_fpr[target_fpr] = dr

    return RobustnessReport(
        threshold_drift_mean=drift_mean,
        threshold_drift_max=drift_max,
        threshold_drift_std=drift_std,
        disagreement_entropy_mean=H_mean,
        disagreement_entropy_std=H_std,
        score_variance_mean=var_mean,
        sensitivity_curve=curve,
        detection_rate_at_fpr=dr_at_fpr,
        false_positive_rate_observed=false_positive_rate,
        false_positive_count=false_positive_count,
        true_positive_count=true_positive_count,
        n_events=len(ensemble_scores),
        n_anomalies_flagged=n_flagged,
        n_injected=n_injected,
    )


def sensitivity_curve(
    ensemble_scores: np.ndarray,
    contamination_range: tuple[float, float] = (0.01, 0.30),
    n_steps: int = 20,
) -> list[tuple[float, float]]:
    """Threshold sensitivity curve over a contamination range.

    Returns
    -------
    list[tuple[float, float]]
        ``[(contamination, tau), ...]`` in ascending contamination order.
    """
    scores = np.asarray(ensemble_scores, dtype=np.float64)
    lo, hi = contamination_range
    result: list[tuple[float, float]] = []
    for c in np.linspace(lo, hi, n_steps):
        pct = 100.0 * (1.0 - float(c))
        tau = float(np.percentile(scores, pct))
        result.append((float(c), tau))
    return result


# ------------------------------------------------------------------
# Internal metric helpers
# ------------------------------------------------------------------

def _compute_drifts(threshold_history: list[float]) -> list[float]:
    """Compute |Δτ| sequence from a list of threshold values."""
    if len(threshold_history) < 2:
        return []
    arr = np.asarray(threshold_history, dtype=np.float64)
    return list(np.abs(np.diff(arr)))


def _disagreement_entropy(per_model_scores: dict[str, np.ndarray]) -> np.ndarray:
    """Per-sample Shannon entropy from softmax-normalized scores."""
    if not per_model_scores:
        return np.array([])

    score_matrix = np.stack(
        [np.asarray(s, dtype=np.float64) + 1e-9 for s in per_model_scores.values()],
        axis=0,
    )
    shifted = score_matrix - score_matrix.max(axis=0, keepdims=True)
    exp_s = np.exp(shifted)
    p = exp_s / exp_s.sum(axis=0, keepdims=True)
    return -(p * np.log(p + 1e-12)).sum(axis=0)


def _score_variance(per_model_scores: dict[str, np.ndarray]) -> np.ndarray:
    """Per-sample variance across model scores."""
    if not per_model_scores:
        return np.array([])
    score_matrix = np.stack(
        [np.asarray(s, dtype=np.float64) for s in per_model_scores.values()], axis=0
    )
    return score_matrix.var(axis=0)


def _detection_rate_at_fpr(
    scores: np.ndarray,
    ground_truth: np.ndarray,
    target_fpr: float,
) -> float:
    """Compute detection rate (TPR) at a given FPR operating point.

    Sweeps thresholds on the score distribution, finds the threshold
    that achieves ``target_fpr`` on non-synthetic events, then measures
    what fraction of synthetic events are caught above that threshold.
    """
    normal_mask = ~ground_truth
    anomaly_mask = ground_truth

    n_normal = normal_mask.sum()
    n_anomaly = anomaly_mask.sum()

    if n_normal == 0 or n_anomaly == 0:
        return 0.0

    # Sweep thresholds in descending order of score
    thresholds = np.sort(scores)[::-1]
    best_dr = 0.0

    for tau in thresholds:
        fp = int((scores[normal_mask] >= tau).sum())
        fpr = fp / n_normal
        if fpr <= target_fpr:
            tp = int((scores[anomaly_mask] >= tau).sum())
            dr = tp / n_anomaly
            best_dr = max(best_dr, dr)

    return best_dr

"""
chimera.evaluation.runner — Benchmarking runner.

Executes a full evaluation cycle:
    1. Load real events.
    2. Inject synthetic anomalies via :mod:`chimera.evaluation.injector`.
    3. Run a *baseline* ensemble (raw per-model scores, naive mean, no normalization).
    4. Run the *Chimera* ensemble (normalized → voted → dynamic threshold).
    5. Compare robustness metrics side by side.

All runs use fixed seeds for full reproducibility.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional, Any

import numpy as np

from chimera.evaluation.injector import inject, InjectionType
from chimera.evaluation.metrics import RobustnessReport, compute_robustness
from chimera.engine.pipeline import EnginePipeline, ScoreResult

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Side-by-side comparison of baseline vs Chimera robustness."""

    baseline: RobustnessReport
    chimera: RobustnessReport

    injection_type: str
    injection_magnitude: float
    n_events_original: int
    n_events_injected: int
    seed: int
    elapsed_seconds: float
    explainability_examples: list[dict[str, Any]]

    def summary_table(self) -> str:
        """Print a formatted comparison table."""
        rows = [
            ("Metric", "Baseline", "Chimera"),
            ("-" * 30, "-" * 12, "-" * 12),
            (
                "Threshold drift mean",
                f"{self.baseline.threshold_drift_mean:.4f}",
                f"{self.chimera.threshold_drift_mean:.4f}",
            ),
            (
                "Threshold drift max",
                f"{self.baseline.threshold_drift_max:.4f}",
                f"{self.chimera.threshold_drift_max:.4f}",
            ),
            (
                "Disagreement entropy (mean)",
                f"{self.baseline.disagreement_entropy_mean:.4f}",
                f"{self.chimera.disagreement_entropy_mean:.4f}",
            ),
            (
                "Score variance (mean)",
                f"{self.baseline.score_variance_mean:.4f}",
                f"{self.chimera.score_variance_mean:.4f}",
            ),
        ]
        for fpr, dr in sorted(self.chimera.detection_rate_at_fpr.items()):
            bl_dr = self.baseline.detection_rate_at_fpr.get(fpr, 0.0)
            rows.append((f"Detection rate @ FPR={fpr:.2f}", f"{bl_dr:.3f}", f"{dr:.3f}"))

        col_widths = [max(len(r[i]) for r in rows) for i in range(3)]
        lines = []
        for row in rows:
            parts = [row[i].ljust(col_widths[i]) for i in range(3)]
            lines.append("  ".join(parts))
        return "\n".join(lines)


def run_benchmark(
    raw_scores_train: dict[str, np.ndarray],
    raw_scores_test: dict[str, np.ndarray],
    events: list[dict],
    ground_truth_mask: Optional[np.ndarray] = None,
    injection_type: InjectionType = "burst_attack",
    injection_magnitude: float = 3.0,
    injection_window: int = 50,
    seed: int = 42,
    engine_config: Optional[dict] = None,
    contamination_range: tuple[float, float] = (0.01, 0.30),
    n_sensitivity_steps: int = 20,
) -> BenchmarkResult:
    """Run a full benchmark comparing baseline vs Chimera robustness.

    Parameters
    ----------
    raw_scores_train:
        Dict of ``model_id`` → raw 1-D training scores per model.
    raw_scores_test:
        Dict of ``model_id`` → raw 1-D test scores per model.
    events:
        Original event list (used for injection; must align with test scores).
    injection_type:
        Attack type to inject for ground truth.
    injection_magnitude:
        Attack intensity.
    injection_window:
        Number of events in the injection frame.
    seed:
        Random seed for deterministic injection.
    engine_config:
        Optional Chimera config dict (passed to :meth:`EnginePipeline.from_config`).
    contamination_range / n_sensitivity_steps:
        For the sensitivity curve in ``RobustnessReport``.

    Returns
    -------
    BenchmarkResult
    """
    t0 = time.monotonic()

    if ground_truth_mask is None:
        injected_events = inject(
            events=events,
            type=injection_type,
            magnitude=injection_magnitude,
            window=injection_window,
            seed=seed,
        )
        n_injected = len(injected_events) - len(events)
        gt_mask = np.zeros(
            len(raw_scores_test[list(raw_scores_test.keys())[0]]), dtype=bool
        )
        if n_injected > 0:
            gt_mask[-min(n_injected, len(gt_mask)):] = True
    else:
        gt_mask = np.asarray(ground_truth_mask, dtype=bool)
        n_injected = int(gt_mask.sum())

    logger.info(
        "[runner] Benchmark start: injection=%s, magnitude=%.1f, seed=%d",
        injection_type, injection_magnitude, seed,
    )

    # 2. Baseline run (naive mean of raw scores, no normalization)
    baseline_report = _run_baseline(
        raw_scores_train, raw_scores_test, gt_mask, contamination_range, n_sensitivity_steps
    )

    # 3. Chimera run (normalized → voted → dynamic threshold)
    chimera_config = engine_config or {}
    pipeline = EnginePipeline.from_config(chimera_config)
    pipeline.fit(raw_scores_train)
    result: ScoreResult = pipeline.score(raw_scores_test, update_threshold=False)

    # Get threshold history from the fitted threshold engine
    threshold_history = [pipeline.threshold.current_threshold or 0.0]

    chimera_report = compute_robustness(
        ensemble_scores=result.ensemble_scores,
        per_model_scores=result.per_model_normalized,
        threshold_history=threshold_history,
        ground_truth_mask=gt_mask,
        contamination_range=contamination_range,
        n_steps=n_sensitivity_steps,
        anomaly_mask=result.anomaly_mask,
    )

    elapsed = time.monotonic() - t0

    bench = BenchmarkResult(
        baseline=baseline_report,
        chimera=chimera_report,
        injection_type=injection_type,
        injection_magnitude=injection_magnitude,
        n_events_original=len(events),
        n_events_injected=n_injected,
        seed=seed,
        elapsed_seconds=elapsed,
        explainability_examples=[],
    )

    logger.info("[runner] Benchmark complete in %.2fs", elapsed)
    _log_comparison(bench)
    return bench


# ------------------------------------------------------------------
# Baseline (no normalization)
# ------------------------------------------------------------------

def _run_baseline(
    train: dict[str, np.ndarray],
    test: dict[str, np.ndarray],
    gt_mask: np.ndarray,
    contamination_range: tuple[float, float],
    n_steps: int,
) -> RobustnessReport:
    """Naive baseline: raw mean of per-model scores, no normalization."""
    # Mean over raw train scores to derive naive threshold
    train_ensemble = np.stack(list(train.values()), axis=0).mean(axis=0)
    test_ensemble = np.stack(list(test.values()), axis=0).mean(axis=0)

    contamination = 0.05
    tau = float(np.percentile(train_ensemble, 100.0 * (1 - contamination)))
    anomaly_mask = test_ensemble >= tau

    # Baseline has no threshold update history
    return compute_robustness(
        ensemble_scores=test_ensemble,
        per_model_scores=test,
        threshold_history=[tau],
        ground_truth_mask=gt_mask,
        contamination_range=contamination_range,
        n_steps=n_steps,
        anomaly_mask=anomaly_mask,
    )


def _log_comparison(bench: BenchmarkResult) -> None:
    logger.info(
        "[runner] Baseline: drift_mean=%.4f  H_mean=%.4f\n"
        "[runner] Chimera:  drift_mean=%.4f  H_mean=%.4f",
        bench.baseline.threshold_drift_mean,
        bench.baseline.disagreement_entropy_mean,
        bench.chimera.threshold_drift_mean,
        bench.chimera.disagreement_entropy_mean,
    )

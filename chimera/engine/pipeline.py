"""
chimera.engine.pipeline — Orchestrated scoring pipeline.

Wires together the three core engine components into a single, coherent
scoring pipeline:

    ScoreNormalizer → EnsembleVoter → DynamicThreshold

Usage
-----
The pipeline is designed to be trained once (offline) and applied at
inference time in batch or streaming mode.

    pipeline = EnginePipeline.from_config(config)
    pipeline.fit(raw_scores_per_model={"if": if_train_scores, "lof": lof_train_scores})
    results = pipeline.score(raw_scores_per_model={"if": if_test_scores, "lof": lof_test_scores})

    results.ensemble_scores      # normalized, voted ensemble score per event
    results.anomaly_mask         # True where score >= threshold
    results.disagreement_entropy # per-event model disagreement
    results.threshold            # current threshold τ
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

from chimera.engine.normalizer import ScoreNormalizer
from chimera.engine.voter import EnsembleVoter, VotingStrategy
from chimera.engine.threshold import DynamicThreshold

logger = logging.getLogger(__name__)


@dataclass
class ScoreResult:
    """Output of a pipeline scoring pass."""

    ensemble_scores: np.ndarray
    """Normalized, voted ensemble score per event (values in [0, 1])."""

    anomaly_mask: np.ndarray
    """Boolean mask: True where ensemble_score >= threshold."""

    disagreement_entropy: np.ndarray
    """Per-event inter-model disagreement entropy."""

    score_variance: np.ndarray
    """Per-event variance across model scores."""

    per_model_normalized: dict[str, np.ndarray] = field(default_factory=dict)
    """Normalized scores per individual model (diagnostic use)."""

    threshold: float = 0.0
    """Threshold τ applied to produce anomaly_mask."""

    threshold_instability: float = 0.0
    """Current threshold instability metric (mean |Δτ|)."""

    n_anomalies: int = 0
    """Count of events flagged as anomalous."""

    hard_floor_hits: int = 0
    """Count of events elevated by identity hard-floor logic."""

    def __post_init__(self) -> None:
        self.n_anomalies = int(self.anomaly_mask.sum())


class EnginePipeline:
    """Full scoring pipeline: normalization → voting → thresholding.

    Parameters
    ----------
    norm_strategy:
        Normalization strategy passed to :class:`~chimera.engine.normalizer.ScoreNormalizer`.
    voting_strategy:
        Voting strategy passed to :class:`~chimera.engine.voter.EnsembleVoter`.
    contamination:
        Expected anomaly fraction, passed to :class:`~chimera.engine.threshold.DynamicThreshold`.
    trim_fraction:
        Used when ``voting_strategy="trimmed_mean"``.
    weights:
        Per-model weights for ``"weighted"`` voting.
    low_variance_threshold / collapse_epsilon / quantile_range:
        Normalization guard parameters.
    recalc_window / max_drift_history:
        Threshold recalculation and drift tracking parameters.
    """

    def __init__(
        self,
        norm_strategy: str = "minmax",
        voting_strategy: VotingStrategy = "mean",
        contamination: float = 0.05,
        trim_fraction: float = 0.1,
        weights: Optional[dict[str, float]] = None,
        low_variance_threshold: float = 1e-4,
        collapse_epsilon: float = 1e-6,
        quantile_range: tuple[float, float] = (0.05, 0.95),
        recalc_window: int = 500,
        max_drift_history: int = 5000,
        identity_hard_floor_enabled: bool = False,
        identity_hard_floor_model: str = "identity_takeover",
        identity_hard_floor: float = 0.58,
        identity_hard_floor_support_model: Optional[str] = "identity_takeover_support",
        identity_hard_floor_support_threshold: float = 0.55,
    ) -> None:
        self.normalizer = ScoreNormalizer(
            strategy=norm_strategy,
            low_variance_threshold=low_variance_threshold,
            collapse_epsilon=collapse_epsilon,
            quantile_range=quantile_range,
        )
        self.voter = EnsembleVoter(
            strategy=voting_strategy,
            trim_fraction=trim_fraction,
            weights=weights or {},
        )
        self.threshold = DynamicThreshold(
            contamination=contamination,
            recalc_window=recalc_window,
            max_drift_history=max_drift_history,
        )
        self.identity_hard_floor_enabled = identity_hard_floor_enabled
        self.identity_hard_floor_model = identity_hard_floor_model
        self.identity_hard_floor = identity_hard_floor
        self.identity_hard_floor_support_model = identity_hard_floor_support_model
        self.identity_hard_floor_support_threshold = identity_hard_floor_support_threshold
        self._fitted: bool = False

    # ------------------------------------------------------------------
    # Training phase
    # ------------------------------------------------------------------

    def fit(self, raw_scores_per_model: dict[str, np.ndarray]) -> "EnginePipeline":
        """Fit normalizer and initial threshold from training scores.

        Parameters
        ----------
        raw_scores_per_model:
            Dict of ``model_id`` → raw 1-D score array from the training set.

        Returns
        -------
        EnginePipeline
            Self, for method chaining.
        """
        logger.info(
            "[pipeline] Fitting on %d models: %s",
            len(raw_scores_per_model),
            list(raw_scores_per_model.keys()),
        )

        # 1. Fit per-model normalizers and get normalized training scores
        normalized: dict[str, np.ndarray] = {}
        for model_id, raw in raw_scores_per_model.items():
            normalized[model_id] = self.normalizer.fit_transform(model_id, raw)
            logger.debug("[pipeline] Normalized '%s'", model_id)

        # 2. Vote to get ensemble training scores
        ensemble_train = self.voter.vote(normalized)

        # 3. Fit initial threshold τ_0
        self.threshold.fit(ensemble_train)

        self._fitted = True
        logger.info(
            "[pipeline] Fit complete. tau_0=%.6f, models=%s",
            self.threshold.current_threshold,
            list(raw_scores_per_model.keys()),
        )
        return self

    # ------------------------------------------------------------------
    # Inference phase
    # ------------------------------------------------------------------

    def score(
        self,
        raw_scores_per_model: dict[str, np.ndarray],
        update_threshold: bool = False,
    ) -> ScoreResult:
        """Score events using fitted normalizer, voter, and threshold.

        Parameters
        ----------
        raw_scores_per_model:
            Dict of ``model_id`` → raw 1-D score array from inference.
        update_threshold:
            If True, recalculate τ from these scores and log drift.
            Useful in streaming mode; set False for standard batch inference.

        Returns
        -------
        ScoreResult
            Full scoring result including ensemble scores, anomaly mask,
            and robustness diagnostics.
        """
        if not self._fitted:
            raise RuntimeError("Call fit() before score().")

        # 1. Normalize
        normalized: dict[str, np.ndarray] = {}
        for model_id, raw in raw_scores_per_model.items():
            normalized[model_id] = self.normalizer.transform(model_id, raw)

        # 2. Vote
        ensemble_scores = self.voter.vote(normalized)

        # 3. Robustness diagnostics
        entropy = self.voter.disagreement_entropy(normalized)
        variance = self.voter.score_variance(normalized)

        # 4. Threshold — optionally update
        if update_threshold:
            tau, delta = self.threshold.update(ensemble_scores)
            logger.debug("[pipeline] Threshold updated: tau=%.6f, drift=%.6f", tau, delta)

        anomaly_mask = self.threshold.predict(ensemble_scores)
        hard_floor_mask = np.zeros_like(anomaly_mask, dtype=bool)
        if self.identity_hard_floor_enabled:
            identity_scores = normalized.get(self.identity_hard_floor_model)
            if identity_scores is not None:
                hard_floor_mask = identity_scores >= self.identity_hard_floor
                if self.identity_hard_floor_support_model is not None:
                    support_scores = normalized.get(self.identity_hard_floor_support_model)
                    if support_scores is None:
                        hard_floor_mask = np.zeros_like(anomaly_mask, dtype=bool)
                    else:
                        hard_floor_mask = hard_floor_mask & (
                            support_scores >= self.identity_hard_floor_support_threshold
                        )
                anomaly_mask = anomaly_mask | hard_floor_mask
                ensemble_scores = np.where(hard_floor_mask, 1.0, ensemble_scores)

        return ScoreResult(
            ensemble_scores=ensemble_scores,
            anomaly_mask=anomaly_mask,
            disagreement_entropy=entropy,
            score_variance=variance,
            per_model_normalized=normalized,
            threshold=self.threshold.current_threshold or 0.0,
            threshold_instability=self.threshold.instability_metric,
            hard_floor_hits=int(hard_floor_mask.sum()),
        )

    # ------------------------------------------------------------------
    # Convenience: sensitivity sweep
    # ------------------------------------------------------------------

    def sensitivity_curve(
        self,
        raw_scores_per_model: dict[str, np.ndarray],
        contamination_range: tuple[float, float] = (0.01, 0.30),
        n_steps: int = 20,
    ) -> list[tuple[float, float]]:
        """Compute how the threshold moves across a contamination range.

        Useful for understanding model calibration and for reporting.
        Returns list of ``(contamination, tau)`` pairs.
        """
        if not self._fitted:
            raise RuntimeError("Call fit() before sensitivity_curve().")

        normalized = {
            m: self.normalizer.transform(m, s)
            for m, s in raw_scores_per_model.items()
        }
        ensemble = self.voter.vote(normalized)
        return self.threshold.sensitivity_at_contamination(
            ensemble, contamination_range=contamination_range, n_steps=n_steps
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, directory: str | Path) -> None:
        """Save all pipeline components to ``directory``."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.normalizer.save(directory / "normalizer.json")
        logger.info("[pipeline] Saved to %s", directory)

    @classmethod
    def load(cls, directory: str | Path, **kwargs) -> "EnginePipeline":
        """Load a previously saved pipeline from ``directory``."""
        directory = Path(directory)
        inst = cls(**kwargs)
        inst.normalizer = ScoreNormalizer.load(directory / "normalizer.json")
        inst._fitted = True
        logger.info("[pipeline] Loaded from %s", directory)
        return inst

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config: dict) -> "EnginePipeline":
        """Construct pipeline from a Chimera config dict.

        Expected keys (all optional, with defaults):
            normalization.strategy, normalization.low_variance_threshold,
            normalization.collapse_epsilon,
            ensemble.voting_strategy, ensemble.trim_fraction, ensemble.weights,
            threshold.contamination, threshold.recalc_window,
            threshold.max_drift_history
        """
        norm_cfg = config.get("normalization", {})
        ens_cfg = config.get("ensemble", {})
        thr_cfg = config.get("threshold", {})
        ident_cfg = config.get("identity_research", {})

        return cls(
            norm_strategy=norm_cfg.get("strategy", "minmax"),
            voting_strategy=ens_cfg.get("voting_strategy", "mean"),
            contamination=thr_cfg.get("contamination", 0.05),
            trim_fraction=ens_cfg.get("trim_fraction", 0.1),
            weights=ens_cfg.get("weights") or {},
            low_variance_threshold=norm_cfg.get("low_variance_threshold", 1e-4),
            collapse_epsilon=norm_cfg.get("collapse_epsilon", 1e-6),
            quantile_range=tuple(norm_cfg.get("quantile_range", [0.05, 0.95])),
            recalc_window=thr_cfg.get("recalc_window", 500),
            max_drift_history=thr_cfg.get("max_drift_history", 5000),
            identity_hard_floor_enabled=ident_cfg.get("scoring_hard_floor_enabled", False),
            identity_hard_floor_model=ident_cfg.get("hard_floor_model", "identity_takeover"),
            identity_hard_floor=ident_cfg.get("takeover_hard_floor", 0.58),
            identity_hard_floor_support_model=ident_cfg.get(
                "hard_floor_support_model",
                "identity_takeover_support",
            ),
            identity_hard_floor_support_threshold=ident_cfg.get(
                "takeover_support_floor",
                0.55,
            ),
        )

    def __repr__(self) -> str:
        return (
            f"EnginePipeline("
            f"norm={self.normalizer.strategy!r}, "
            f"voting={self.voter.strategy!r}, "
            f"contamination={self.threshold.contamination}, "
            f"fitted={self._fitted})"
        )

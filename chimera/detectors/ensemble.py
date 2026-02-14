"""
Ensemble detector for Chimera.

Combines multiple detectors using a voting strategy: each detector
contributes a normalized anomaly score, and the ensemble aggregates
them into a final verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
import logging

import numpy as np
import pandas as pd

from sklearn.preprocessing import MinMaxScaler

from chimera.detectors.base import BaseDetector, DetectorConfig, DetectorMetadata
from chimera.registry import DetectorRegistry

logger = logging.getLogger(__name__)


@dataclass
class EnsembleConfig(DetectorConfig):
    """Configuration for the ensemble detector."""

    strategy: str = "mean"  # "mean", "median", "max"
    detector_names: list[str] = field(
        default_factory=lambda: ["isolation_forest", "lof"]
    )
    weights: Optional[list[float]] = None  # per-detector weights (for "mean")
    contamination: float = 0.05  # Approximate anomaly rate for thresholding


@DetectorRegistry.register
class EnsembleDetector(BaseDetector):
    """
    Ensemble anomaly detector that combines multiple models.

    Strategies:
    - **mean**: Weighted average of normalized scores (default).
    - **median**: Median of normalized scores — robust to outlier models.
    - **max**: Most-anomalous score wins — high-recall, aggressive.
    """

    name = "ensemble"
    description = "Ensemble — combines multiple detectors via voting"

    def __init__(self, config: Optional[EnsembleConfig] = None):
        super().__init__(config=config or EnsembleConfig())
        self.config: EnsembleConfig
        self.detectors: list[BaseDetector] = []
        self.score_scalers: list[MinMaxScaler] = []
        self.threshold: float = 0.5

    def fit(
        self, features: pd.DataFrame, feature_names: Optional[list[str]] = None
    ) -> "EnsembleDetector":
        self.feature_names = feature_names or features.columns.tolist()

        logger.info(
            f"Training ensemble ({self.config.strategy}) with detectors: "
            f"{self.config.detector_names}"
        )

        self.detectors = []
        self.score_scalers = []
        
        # 1. Fit all detectors
        for det_name in self.config.detector_names:
            det = DetectorRegistry.create(det_name)
            # Ensure deterministic behavior by propagating random_state
            if hasattr(det.config, "random_state"):
                det.config.random_state = self.config.random_state
            
            det.fit(features, feature_names=self.feature_names)
            self.detectors.append(det)

        # 2. Normalize scores
        # We need to fit scalers on the training scores
        normalized_scores_list = []
        for det in self.detectors:
            raw_scores = det.score(features).reshape(-1, 1)
            scaler = MinMaxScaler(feature_range=(0, 1))
            scaled = scaler.fit_transform(raw_scores).flatten()
            self.score_scalers.append(scaler)
            normalized_scores_list.append(scaled)

        # 3. Compute ensemble threshold
        # Aggregate normalized scores
        score_matrix = np.column_stack(normalized_scores_list)
        ensemble_scores = self._aggregate_scores(score_matrix)
        
        # Determine threshold at configured contamination percentile
        # Lower scores = more anomalous. So we want the bottom X%.
        self.threshold = float(np.percentile(ensemble_scores, self.config.contamination * 100))
        logger.info(f"Ensemble threshold set to {self.threshold:.4f} (contamination={self.config.contamination})")

        # Collect ensemble metadata
        all_stats = {}
        for det in self.detectors:
            if det.metadata and det.metadata.training_stats:
                all_stats[det.name] = det.metadata.training_stats

        self.metadata = DetectorMetadata(
            detector_type=self.name,
            training_samples=len(features),
            feature_count=len(self.feature_names),
            feature_names=self.feature_names,
            config=self.config.to_dict(),
            training_stats={
                "strategy": self.config.strategy,
                "member_count": len(self.detectors),
                "member_stats": all_stats,
            },
        )

        # We use the first detector's scaler for the explain() fallback
        if self.detectors:
            self.scaler = self.detectors[0].scaler

        self._is_fitted = True
        logger.info(f"Ensemble training complete with {len(self.detectors)} members")
        return self

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        scores = self.score(features)
        # Anomaly if aggregated score < 0
        return np.where(scores < 0, -1, 1)

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        scores = self.score(features)
        # Anomaly if score < threshold
        return np.where(scores < self.threshold, -1, 1)

    def score(self, features: pd.DataFrame) -> np.ndarray:
        self._check_fitted()

        normalized_scores_list = []
        for i, det in enumerate(self.detectors):
            raw_scores = det.score(features).reshape(-1, 1)
            # Clip to [0, 1] to handle out-of-distribution values
            scaled = self.score_scalers[i].transform(raw_scores).flatten()
            scaled = np.clip(scaled, 0, 1)
            normalized_scores_list.append(scaled)

        score_matrix = np.column_stack(normalized_scores_list)
        return self._aggregate_scores(score_matrix)

    def _aggregate_scores(self, score_matrix: np.ndarray) -> np.ndarray:
        """Combine normalized scores using the configured strategy."""

        weights = self.config.weights
        if weights and len(weights) == score_matrix.shape[1]:
            w = np.array(weights)
        else:
            w = np.ones(score_matrix.shape[1])

        strategy = self.config.strategy
        if strategy == "mean":
            return np.average(score_matrix, axis=1, weights=w)
        elif strategy == "median":
            return np.median(score_matrix, axis=1)
        elif strategy == "max":
            # "Max anomaly" = minimum score (most negative wins)
            return np.min(score_matrix, axis=1)
        else:
            return np.average(score_matrix, axis=1, weights=w)

    def explain(
        self, features: pd.DataFrame, top_k: int = 5
    ) -> list[dict[str, Any]]:
        """Aggregate explanations from all member detectors."""
        self._check_fitted()

        # Collect explanations from each detector
        all_explanations: list[list[dict]] = []
        for det in self.detectors:
            all_explanations.append(det.explain(features, top_k=top_k))

        # Merge: for each sample, combine top features across detectors
        n_samples = len(features)
        merged = []
        for i in range(n_samples):
            feature_scores: dict[str, list[float]] = {}
            for det_explanations in all_explanations:
                if i < len(det_explanations):
                    for feat in det_explanations[i].get("top_features", []):
                        fname = feat["feature"]
                        feature_scores.setdefault(fname, []).append(feat["z_score"])

            # Average z-scores across detectors, take top_k
            avg_features = [
                {"feature": fname, "z_score": float(np.mean(zs)), "value": 0.0}
                for fname, zs in feature_scores.items()
            ]
            avg_features.sort(key=lambda x: x["z_score"], reverse=True)

            merged.append(
                {"sample_index": i, "top_features": avg_features[:top_k]}
            )

        return merged

    def _get_save_payload(self) -> dict[str, Any]:
        payload = super()._get_save_payload()
        payload["member_payloads"] = [
            det._get_save_payload() for det in self.detectors
        ]
        payload["member_payloads"] = [
            det._get_save_payload() for det in self.detectors
        ]
        payload["score_scalers"] = self.score_scalers
        payload["threshold"] = self.threshold
        payload["detector_names"] = self.config.detector_names
        return payload

    def _restore_from_payload(self, payload: dict[str, Any]) -> None:
        self.config = EnsembleConfig()
        super()._restore_from_payload(payload)

        self.detectors = []
        for member_payload in payload.get("member_payloads", []):
            det_type = member_payload.get("detector_type", "isolation_forest")
            det_cls = DetectorRegistry.get(det_type)
            det = det_cls.__new__(det_cls)
            det._restore_from_payload(member_payload)
            self.detectors.append(det)
        
        self.score_scalers = payload.get("score_scalers", [])
        self.threshold = payload.get("threshold", 0.5)

        if self.detectors:
            self.scaler = self.detectors[0].scaler

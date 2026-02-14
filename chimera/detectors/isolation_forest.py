"""
Isolation Forest detector for Chimera.

Wraps scikit-learn's IsolationForest behind the BaseDetector interface
with conservative defaults optimized for authentication-log analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
import logging

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from chimera.detectors.base import BaseDetector, DetectorConfig, DetectorMetadata
from chimera.registry import DetectorRegistry

logger = logging.getLogger(__name__)


@dataclass
class IsolationForestConfig(DetectorConfig):
    """Configuration specific to Isolation Forest."""

    n_estimators: int = 150
    max_samples: Any = "auto"
    contamination: Any = "auto"
    max_features: Any = 1.0
    bootstrap: bool = False
    verbose: int = 0
    warm_start: bool = False


@DetectorRegistry.register
class IsolationForestDetector(BaseDetector):
    """
    Isolation Forest anomaly detector.

    Conservative defaults tuned for security research:
    - 150 estimators for stable results
    - Auto contamination (let the model decide)
    - Standard scaling by default
    """

    name = "isolation_forest"
    description = "Isolation Forest — fast, tree-based anomaly detection"

    def __init__(self, config: Optional[IsolationForestConfig] = None):
        super().__init__(config=config or IsolationForestConfig())
        self.config: IsolationForestConfig
        self.model: Optional[IsolationForest] = None

    def fit(
        self, features: pd.DataFrame, feature_names: Optional[list[str]] = None
    ) -> "IsolationForestDetector":
        logger.info(
            f"Training IsolationForest on {len(features)} samples, "
            f"{features.shape[1]} features"
        )

        self.feature_names = feature_names or features.columns.tolist()
        numeric = features.select_dtypes(include=[np.number]).fillna(0)

        if numeric.empty:
            raise ValueError("No numeric features found in training data")

        self._init_scaler()
        scaled = self.scaler.fit_transform(numeric)

        self.model = IsolationForest(
            n_estimators=self.config.n_estimators,
            max_samples=self.config.max_samples,
            contamination=self.config.contamination,
            max_features=self.config.max_features,
            bootstrap=self.config.bootstrap,
            n_jobs=self.config.n_jobs,
            random_state=self.config.random_state,
            verbose=self.config.verbose,
            warm_start=self.config.warm_start,
        )
        self.model.fit(scaled)

        scores = self.model.decision_function(scaled)
        self.metadata = DetectorMetadata(
            detector_type=self.name,
            training_samples=len(features),
            feature_count=numeric.shape[1],
            feature_names=self.feature_names,
            config=self.config.to_dict(),
            training_stats={
                "score_mean": float(np.mean(scores)),
                "score_std": float(np.std(scores)),
                "score_min": float(np.min(scores)),
                "score_max": float(np.max(scores)),
                "score_median": float(np.median(scores)),
                "estimated_anomalies": int(np.sum(scores < 0)),
            },
        )
        self._is_fitted = True
        logger.info(
            f"IsolationForest training complete. "
            f"Estimated anomalies: {self.metadata.training_stats['estimated_anomalies']}"
        )
        return self

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        return self.model.predict(self._prepare_features(features))

    def score(self, features: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        return self.model.decision_function(self._prepare_features(features))

    # ── Persistence overrides ────────────────────────────────────

    def _get_save_payload(self) -> dict[str, Any]:
        payload = super()._get_save_payload()
        payload["model"] = self.model
        return payload

    def _restore_from_payload(self, payload: dict[str, Any]) -> None:
        self.config = IsolationForestConfig()
        super()._restore_from_payload(payload)
        self.model = payload.get("model")

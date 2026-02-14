"""
Local Outlier Factor detector for Chimera.

LOF measures the local deviation of density of a given sample
with respect to its neighbors, making it effective for detecting
contextual anomalies that Isolation Forest may miss.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
import logging

import numpy as np
import pandas as pd
from sklearn.neighbors import LocalOutlierFactor

from chimera.detectors.base import BaseDetector, DetectorConfig, DetectorMetadata
from chimera.registry import DetectorRegistry

logger = logging.getLogger(__name__)


@dataclass
class LOFConfig(DetectorConfig):
    """Configuration for the Local Outlier Factor detector."""

    n_neighbors: int = 20
    contamination: Any = "auto"
    metric: str = "minkowski"
    novelty: bool = True  # Must be True for predict/score on new data


@DetectorRegistry.register
class LOFDetector(BaseDetector):
    """
    Local Outlier Factor anomaly detector.

    Good for detecting samples that are locally sparse relative to
    their neighbors — catches contextual anomalies like a user
    behaving normally in aggregate but oddly for *their* cluster.
    """

    name = "lof"
    description = "Local Outlier Factor — density-based contextual anomaly detection"

    def __init__(self, config: Optional[LOFConfig] = None):
        super().__init__(config=config or LOFConfig())
        self.config: LOFConfig
        self.model: Optional[LocalOutlierFactor] = None

    def fit(
        self, features: pd.DataFrame, feature_names: Optional[list[str]] = None
    ) -> "LOFDetector":
        logger.info(
            f"Training LOF on {len(features)} samples, "
            f"{features.shape[1]} features"
        )

        self.feature_names = feature_names or features.columns.tolist()
        numeric = features.select_dtypes(include=[np.number]).fillna(0)

        if numeric.empty:
            raise ValueError("No numeric features found in training data")

        self._init_scaler()
        scaled = self.scaler.fit_transform(numeric)

        self.model = LocalOutlierFactor(
            n_neighbors=min(self.config.n_neighbors, len(scaled) - 1),
            contamination=self.config.contamination,
            metric=self.config.metric,
            novelty=self.config.novelty,
            n_jobs=self.config.n_jobs,
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
            f"LOF training complete. "
            f"Estimated anomalies: {self.metadata.training_stats['estimated_anomalies']}"
        )
        return self

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        return self.model.predict(self._prepare_features(features))

    def score(self, features: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        return self.model.decision_function(self._prepare_features(features))

    def _get_save_payload(self) -> dict[str, Any]:
        payload = super()._get_save_payload()
        payload["model"] = self.model
        return payload

    def _restore_from_payload(self, payload: dict[str, Any]) -> None:
        self.config = LOFConfig()
        super()._restore_from_payload(payload)
        self.model = payload.get("model")

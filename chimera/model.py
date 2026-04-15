"""
Anomaly detection model — high-level API.

This module preserves backward compatibility with v0.1.0 while
delegating to the new detector subsystem under ``chimera.detectors``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union
import json
import logging

import numpy as np
import pandas as pd
import joblib

# Re-export detector building blocks so existing imports still work
from chimera.detectors.base import DetectorConfig, DetectorMetadata, BaseDetector
from chimera.detectors.isolation_forest import (
    IsolationForestDetector,
    IsolationForestConfig,
)
from chimera.registry import DetectorRegistry

logger = logging.getLogger(__name__)


# ── Backward-compatible aliases ──────────────────────────────────


@dataclass
class ModelConfig:
    """
    Legacy configuration class (v0.1.0 compatibility).

    New code should use ``DetectorConfig`` or detector-specific configs.
    """

    n_estimators: int = 150
    max_samples: Any = "auto"
    contamination: Any = "auto"
    max_features: Any = 1.0
    bootstrap: bool = False
    n_jobs: int = -1
    random_state: int = 42
    verbose: int = 0
    warm_start: bool = False
    scaler_type: str = "standard"
    score_threshold: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelConfig":
        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


ModelMetadata = DetectorMetadata  # alias for backward compat


class AnomalyDetector:
    """
    High-level anomaly detector — backward-compatible with v0.1.0.

    Internally delegates to the detector registry so callers can
    switch algorithms transparently::

        # Classic usage (unchanged from v0.1)
        detector = AnomalyDetector()
        detector.fit(features)
        scores = detector.score(features)

        # New: pick a different algorithm
        detector = AnomalyDetector.from_registry("lof")

        # New: use an ensemble
        detector = AnomalyDetector.from_registry("ensemble")
    """

    def __init__(self, config: Optional[ModelConfig] = None, *, detector_name: str = "isolation_forest"):
        self.config = config or ModelConfig()
        self._detector: BaseDetector = self._build_detector(detector_name)

    def _build_detector(self, name: str) -> BaseDetector:
        if name == "isolation_forest":
            cfg = IsolationForestConfig(
                n_estimators=self.config.n_estimators,
                max_samples=self.config.max_samples,
                contamination=self.config.contamination,
                max_features=self.config.max_features,
                bootstrap=self.config.bootstrap,
                verbose=self.config.verbose,
                warm_start=self.config.warm_start,
                scaler_type=self.config.scaler_type,
                random_state=self.config.random_state,
                n_jobs=self.config.n_jobs,
            )
            return IsolationForestDetector(config=cfg)
        return DetectorRegistry.create(name)

    # ── Factory ──────────────────────────────────────────────────

    @classmethod
    def from_registry(cls, name: str, **kwargs: Any) -> "AnomalyDetector":
        """Create a detector via the registry by name."""
        instance = cls.__new__(cls)
        instance.config = ModelConfig()
        instance._detector = DetectorRegistry.create(name, **kwargs)
        return instance

    # ── Delegated API ────────────────────────────────────────────

    def fit(self, features: pd.DataFrame, feature_names: Optional[list[str]] = None) -> "AnomalyDetector":
        self._detector.fit(features, feature_names=feature_names)
        return self

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        return self._detector.predict(features)

    def score(self, features: pd.DataFrame) -> np.ndarray:
        return self._detector.score(features)

    def score_samples(self, features: pd.DataFrame) -> np.ndarray:
        # Flip sign for compatibility
        return -self._detector.score(features)

    def explain_features(self, features: pd.DataFrame, top_k: int = 5) -> list[dict[str, Any]]:
        return self._detector.explain(features, top_k=top_k)

    # ── Properties & pass-through ────────────────────────────────

    @property
    def model(self):
        return getattr(self._detector, "model", None)

    @property
    def scaler(self):
        return self._detector.scaler

    @property
    def metadata(self) -> Optional[DetectorMetadata]:
        return self._detector.metadata

    @metadata.setter
    def metadata(self, value):
        self._detector.metadata = value

    @property
    def feature_names(self) -> list[str]:
        return self._detector.feature_names

    @feature_names.setter
    def feature_names(self, value):
        self._detector.feature_names = value

    @property
    def _is_fitted(self) -> bool:
        return self._detector._is_fitted

    # ── Persistence ──────────────────────────────────────────────

    def save(
        self,
        path: Union[str, Path],
        manifest: Optional[Any] = None,
    ) -> None:
        path = Path(path)
        if path.suffix == "":
            path = path / "chimera_model.joblib"
        self._detector.save(path, manifest=manifest)

    @classmethod
    def load(
        cls,
        path: Union[str, Path],
        *,
        manifest: Optional[Any] = None,
        expected_digest: Optional[str] = None,
        allow_unverified: bool = False,
    ) -> "AnomalyDetector":
        detector = BaseDetector.load(
            path,
            manifest=manifest,
            expected_digest=expected_digest,
            allow_unverified=allow_unverified,
        )
        instance = cls.__new__(cls)
        instance.config = ModelConfig()
        instance._detector = detector
        return instance

    def get_model_info(self) -> dict[str, Any]:
        return self._detector.get_info()

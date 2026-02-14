"""
Base detector interface for Chimera anomaly detection.

All detectors must implement this ABC to participate in the
registry and ensemble systems.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union
import json
import logging

import numpy as np
import pandas as pd
import joblib

logger = logging.getLogger(__name__)


@dataclass
class DetectorConfig:
    """
    Base configuration for all detectors.

    Subclass this for detector-specific configuration.
    """

    scaler_type: str = "standard"  # "standard" or "robust"
    random_state: int = 42
    n_jobs: int = -1

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to dictionary."""
        return {k: v for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DetectorConfig":
        """Deserialize config from dictionary."""
        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


@dataclass
class DetectorMetadata:
    """Metadata about a trained detector."""

    detector_type: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    version: str = "0.2.0"
    training_samples: int = 0
    feature_count: int = 0
    feature_names: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    training_stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_type": self.detector_type,
            "created_at": self.created_at,
            "version": self.version,
            "training_samples": self.training_samples,
            "feature_count": self.feature_count,
            "feature_names": self.feature_names,
            "config": self.config,
            "training_stats": self.training_stats,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DetectorMetadata":
        return cls(
            detector_type=data.get("detector_type", ""),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            version=data.get("version", "0.2.0"),
            training_samples=data.get("training_samples", 0),
            feature_count=data.get("feature_count", 0),
            feature_names=data.get("feature_names", []),
            config=data.get("config", {}),
            training_stats=data.get("training_stats", {}),
        )


class BaseDetector(ABC):
    """
    Abstract base class for all anomaly detectors.

    Every detector in Chimera must implement this interface, enabling
    plug-and-play model registration, ensemble combinations, and
    consistent save/load semantics.
    """

    # Override in subclass
    name: str = "base"
    description: str = "Base detector"

    def __init__(self, config: Optional[DetectorConfig] = None):
        self.config = config or DetectorConfig()
        self.metadata: Optional[DetectorMetadata] = None
        self.feature_names: list[str] = []
        self.scaler: Any = None
        self._is_fitted: bool = False

    @abstractmethod
    def fit(
        self, features: pd.DataFrame, feature_names: Optional[list[str]] = None
    ) -> "BaseDetector":
        """
        Train the detector on feature data.

        Args:
            features: DataFrame of numeric features.
            feature_names: Optional feature name override.

        Returns:
            Self for method chaining.
        """
        ...

    @abstractmethod
    def predict(self, features: pd.DataFrame) -> np.ndarray:
        """
        Predict anomaly labels: 1 = normal, -1 = anomaly.

        Args:
            features: DataFrame of numeric features.

        Returns:
            Array of integer predictions.
        """
        ...

    @abstractmethod
    def score(self, features: pd.DataFrame) -> np.ndarray:
        """
        Compute anomaly scores. Lower (more negative) = more anomalous.

        Args:
            features: DataFrame of numeric features.

        Returns:
            Array of float scores.
        """
        ...

    def explain(
        self, features: pd.DataFrame, top_k: int = 5
    ) -> list[dict[str, Any]]:
        """
        Explain feature contributions for each sample.

        Default implementation uses z-score distance from training mean.
        Subclasses may override with algorithm-specific explanations.
        """
        self._check_fitted()
        prepared = self._prepare_features(features)

        explanations = []
        for i in range(len(prepared)):
            sample = prepared[i]

            if hasattr(self.scaler, "mean_") and hasattr(self.scaler, "scale_"):
                z_scores = np.abs(
                    (sample - self.scaler.mean_)
                    / np.where(self.scaler.scale_ == 0, 1, self.scaler.scale_)
                )
            else:
                z_scores = np.abs(sample)

            top_indices = np.argsort(z_scores)[-top_k:][::-1]

            explanations.append(
                {
                    "sample_index": i,
                    "top_features": [
                        {
                            "feature": (
                                self.feature_names[idx]
                                if idx < len(self.feature_names)
                                else f"feature_{idx}"
                            ),
                            "value": float(sample[idx]),
                            "z_score": float(z_scores[idx]),
                        }
                        for idx in top_indices
                    ],
                }
            )
        return explanations

    # ── Scaling helpers ──────────────────────────────────────────

    def _init_scaler(self) -> None:
        """Initialize the feature scaler based on config."""
        from sklearn.preprocessing import StandardScaler, RobustScaler

        if self.config.scaler_type == "robust":
            self.scaler = RobustScaler()
        else:
            self.scaler = StandardScaler()

    def _prepare_features(self, features: pd.DataFrame) -> np.ndarray:
        """Scale and clean features for model input."""
        numeric = features.select_dtypes(include=[np.number]).fillna(0)
        return self.scaler.transform(numeric)

    # ── Persistence ──────────────────────────────────────────────

    def save(self, path: Union[str, Path]) -> None:
        """Save the trained detector to disk."""
        self._check_fitted()
        path = Path(path)
        if path.suffix == "":
            path = path / f"chimera_{self.name}.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = self._get_save_payload()
        joblib.dump(payload, path)

        # Side-car metadata JSON
        meta_path = path.parent / f"{path.stem}_metadata.json"
        with open(meta_path, "w") as f:
            json.dump(payload.get("metadata", {}), f, indent=2)

        logger.info(f"Detector '{self.name}' saved to {path}")

    @classmethod
    def load(cls, path: Union[str, Path]) -> "BaseDetector":
        """Load a trained detector from disk."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Detector file not found: {path}")

        payload = joblib.load(path)

        # Resolve the correct subclass via registry
        detector_type = payload.get("detector_type", cls.name)
        from chimera.registry import DetectorRegistry

        detector_cls = DetectorRegistry.get(detector_type, cls)
        instance = detector_cls.__new__(detector_cls)
        instance._restore_from_payload(payload)

        logger.info(f"Detector '{instance.name}' loaded from {path}")
        return instance

    def _get_save_payload(self) -> dict[str, Any]:
        """Override in subclass to add model-specific fields."""
        return {
            "detector_type": self.name,
            "scaler": self.scaler,
            "metadata": self.metadata.to_dict() if self.metadata else {},
            "feature_names": self.feature_names,
            "config": self.config.to_dict(),
            "is_fitted": self._is_fitted,
        }

    def _restore_from_payload(self, payload: dict[str, Any]) -> None:
        """Override in subclass to restore model-specific fields."""
        config_cls = type(self.config) if hasattr(self, "config") else DetectorConfig
        self.config = config_cls.from_dict(payload.get("config", {}))
        self.scaler = payload.get("scaler")
        self.feature_names = payload.get("feature_names", [])
        self._is_fitted = payload.get("is_fitted", True)

        meta_dict = payload.get("metadata", {})
        self.metadata = DetectorMetadata.from_dict(meta_dict) if meta_dict else None

    # ── Guards ───────────────────────────────────────────────────

    def _check_fitted(self) -> None:
        if not self._is_fitted:
            raise RuntimeError(
                f"Detector '{self.name}' must be fitted before use. Call fit() first."
            )

    def get_info(self) -> dict[str, Any]:
        """Return summary info about this detector."""
        info: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "is_fitted": self._is_fitted,
            "config": self.config.to_dict(),
        }
        if self.metadata:
            info["metadata"] = self.metadata.to_dict()
        return info

    def __repr__(self) -> str:
        state = "fitted" if self._is_fitted else "not fitted"
        return f"<{type(self).__name__}(name={self.name!r}, {state})>"

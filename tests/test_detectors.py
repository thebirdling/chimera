"""
Tests for the detector registry and built-in detectors.
"""

import pytest
import numpy as np
import pandas as pd
import tempfile
from pathlib import Path

from chimera.engine.integrity import IntegrityManifest
from chimera.registry import DetectorRegistry
from chimera.detectors.base import BaseDetector, DetectorConfig, DetectorMetadata
from chimera.detectors.isolation_forest import IsolationForestDetector, IsolationForestConfig
from chimera.detectors.lof import LOFDetector, LOFConfig
from chimera.detectors.ensemble import EnsembleDetector, EnsembleConfig


@pytest.fixture
def sample_features():
    """Generate sample numeric feature DataFrame."""
    np.random.seed(42)
    n_samples = 100
    return pd.DataFrame({
        "feature_a": np.random.randn(n_samples),
        "feature_b": np.random.randn(n_samples) * 2,
        "feature_c": np.random.uniform(0, 1, n_samples),
        "feature_d": np.random.exponential(1, n_samples),
    })


class TestDetectorRegistry:
    def test_builtin_detectors_registered(self):
        """Built-in detectors should be auto-registered on import."""
        names = DetectorRegistry.names()
        assert "isolation_forest" in names
        assert "lof" in names
        assert "ensemble" in names

    def test_get_detector(self):
        cls = DetectorRegistry.get("isolation_forest")
        assert cls is IsolationForestDetector

    def test_get_unknown_raises(self):
        with pytest.raises(KeyError, match="Unknown detector"):
            DetectorRegistry.get("nonexistent_detector")

    def test_create_factory(self):
        det = DetectorRegistry.create("isolation_forest")
        assert isinstance(det, IsolationForestDetector)

    def test_list_detectors(self):
        detectors = DetectorRegistry.list_detectors()
        assert len(detectors) >= 3
        names = [name for name, _ in detectors]
        assert "isolation_forest" in names


class TestIsolationForestDetector:
    def test_fit_predict_score(self, sample_features):
        det = IsolationForestDetector()
        det.fit(sample_features)

        predictions = det.predict(sample_features)
        assert len(predictions) == len(sample_features)
        assert set(np.unique(predictions)).issubset({-1, 1})

        scores = det.score(sample_features)
        assert len(scores) == len(sample_features)

    def test_metadata_populated(self, sample_features):
        det = IsolationForestDetector()
        det.fit(sample_features)

        assert det.metadata is not None
        assert det.metadata.detector_type == "isolation_forest"
        assert det.metadata.training_samples == len(sample_features)
        assert det.metadata.feature_count == sample_features.shape[1]
        assert "score_mean" in det.metadata.training_stats

    def test_explain(self, sample_features):
        det = IsolationForestDetector()
        det.fit(sample_features)

        explanations = det.explain(sample_features.head(5), top_k=3)
        assert len(explanations) == 5
        assert "top_features" in explanations[0]
        assert len(explanations[0]["top_features"]) <= 3

    def test_save_load(self, sample_features, tmp_path):
        det = IsolationForestDetector()
        det.fit(sample_features)

        save_path = tmp_path / "test_if.joblib"
        manifest = IntegrityManifest(tmp_path / "integrity_manifest.json")
        det.save(save_path, manifest=manifest)

        loaded = BaseDetector.load(save_path, manifest=manifest)
        assert isinstance(loaded, IsolationForestDetector)
        assert loaded._is_fitted

        original_scores = det.score(sample_features)
        loaded_scores = loaded.score(sample_features)
        np.testing.assert_array_almost_equal(original_scores, loaded_scores)

    def test_unfitted_raises(self, sample_features):
        det = IsolationForestDetector()
        with pytest.raises(RuntimeError, match="must be fitted"):
            det.predict(sample_features)

    def test_custom_config(self, sample_features):
        cfg = IsolationForestConfig(n_estimators=50, scaler_type="robust")
        det = IsolationForestDetector(config=cfg)
        det.fit(sample_features)
        assert det._is_fitted


class TestLOFDetector:
    def test_fit_predict_score(self, sample_features):
        det = LOFDetector()
        det.fit(sample_features)

        predictions = det.predict(sample_features)
        assert len(predictions) == len(sample_features)

        scores = det.score(sample_features)
        assert len(scores) == len(sample_features)

    def test_metadata(self, sample_features):
        det = LOFDetector()
        det.fit(sample_features)
        assert det.metadata.detector_type == "lof"

    def test_save_load(self, sample_features, tmp_path):
        det = LOFDetector()
        det.fit(sample_features)

        save_path = tmp_path / "test_lof.joblib"
        manifest = IntegrityManifest(tmp_path / "integrity_manifest.json")
        det.save(save_path, manifest=manifest)

        loaded = BaseDetector.load(save_path, manifest=manifest)
        assert isinstance(loaded, LOFDetector)


class TestEnsembleDetector:
    def test_fit_predict_score(self, sample_features):
        det = EnsembleDetector()
        det.fit(sample_features)

        predictions = det.predict(sample_features)
        assert len(predictions) == len(sample_features)

        scores = det.score(sample_features)
        assert len(scores) == len(sample_features)

    def test_ensemble_has_members(self, sample_features):
        cfg = EnsembleConfig(detector_names=["isolation_forest", "lof"])
        det = EnsembleDetector(config=cfg)
        det.fit(sample_features)

        assert len(det.detectors) == 2

    def test_explain(self, sample_features):
        det = EnsembleDetector()
        det.fit(sample_features)

        explanations = det.explain(sample_features.head(3), top_k=2)
        assert len(explanations) == 3

    def test_save_load(self, sample_features, tmp_path):
        det = EnsembleDetector()
        det.fit(sample_features)

        save_path = tmp_path / "test_ensemble.joblib"
        manifest = IntegrityManifest(tmp_path / "integrity_manifest.json")
        det.save(save_path, manifest=manifest)

        loaded = BaseDetector.load(save_path, manifest=manifest)
        assert isinstance(loaded, EnsembleDetector)
        assert len(loaded.detectors) == 2

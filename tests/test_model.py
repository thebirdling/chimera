"""Tests for model module."""

from datetime import datetime
from pathlib import Path
import tempfile

import pytest
import numpy as np
import pandas as pd

from chimera.engine.integrity import IntegrityManifest
from chimera.model import AnomalyDetector, ModelConfig, ModelMetadata


class TestModelConfig:
    """Tests for ModelConfig."""
    
    def test_default_config(self):
        config = ModelConfig()
        assert config.n_estimators == 150
        assert config.contamination == "auto"
        assert config.scaler_type == "standard"
    
    def test_to_dict(self):
        config = ModelConfig(n_estimators=200)
        d = config.to_dict()
        assert d["n_estimators"] == 200
        assert "random_state" in d
    
    def test_from_dict(self):
        data = {"n_estimators": 200, "contamination": 0.1}
        config = ModelConfig.from_dict(data)
        assert config.n_estimators == 200
        assert config.contamination == 0.1


class TestAnomalyDetector:
    """Tests for AnomalyDetector."""
    
    def test_fit(self):
        detector = AnomalyDetector()
        
        # Create sample features
        np.random.seed(42)
        features = pd.DataFrame({
            "feature_a": np.random.randn(100),
            "feature_b": np.random.randn(100),
        })
        
        detector.fit(features)
        
        assert detector._is_fitted is True
        assert detector.metadata is not None
        assert detector.metadata.training_samples == 100
    
    def test_predict(self):
        detector = AnomalyDetector()
        
        np.random.seed(42)
        train_features = pd.DataFrame({
            "feature_a": np.random.randn(100),
            "feature_b": np.random.randn(100),
        })
        
        detector.fit(train_features)
        
        # Predict on same data
        predictions = detector.predict(train_features)
        
        assert len(predictions) == 100
        assert all(p in [1, -1] for p in predictions)
    
    def test_score(self):
        detector = AnomalyDetector()
        
        np.random.seed(42)
        features = pd.DataFrame({
            "feature_a": np.random.randn(100),
            "feature_b": np.random.randn(100),
        })
        
        detector.fit(features)
        scores = detector.score(features)
        
        assert len(scores) == 100
        assert all(isinstance(s, (int, float)) for s in scores)
    
    def test_explain_features(self):
        detector = AnomalyDetector()
        
        np.random.seed(42)
        features = pd.DataFrame({
            "feature_a": np.random.randn(100),
            "feature_b": np.random.randn(100),
        })
        
        detector.fit(features, feature_names=["feature_a", "feature_b"])
        
        explanations = detector.explain_features(features.head(5), top_k=2)
        
        assert len(explanations) == 5
        assert "top_features" in explanations[0]
        assert len(explanations[0]["top_features"]) == 2
    
    def test_save_and_load(self):
        detector = AnomalyDetector()
        
        np.random.seed(42)
        features = pd.DataFrame({
            "feature_a": np.random.randn(100),
            "feature_b": np.random.randn(100),
        })
        
        detector.fit(features, feature_names=["feature_a", "feature_b"])
        
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model.joblib"
            manifest = IntegrityManifest(Path(tmpdir) / "integrity_manifest.json")
            detector.save(model_path, manifest=manifest)
            
            # Load model
            loaded = AnomalyDetector.load(model_path, manifest=manifest)
            
            assert loaded._is_fitted is True
            assert loaded.feature_names == ["feature_a", "feature_b"]
            
            # Should produce same predictions
            original_scores = detector.score(features)
            loaded_scores = loaded.score(features)
            np.testing.assert_array_almost_equal(original_scores, loaded_scores)
    
    def test_not_fitted_error(self):
        detector = AnomalyDetector()
        
        features = pd.DataFrame({"a": [1, 2, 3]})
        
        with pytest.raises(RuntimeError, match="fitted"):
            detector.predict(features)

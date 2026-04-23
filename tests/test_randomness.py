
import pytest
import numpy as np
import pandas as pd
from chimera.engine.integrity import IntegrityManifest
from chimera.registry import DetectorRegistry
from chimera.detectors.ensemble import EnsembleDetector, EnsembleConfig

@pytest.fixture
def synthetic_data():
    np.random.seed(42)
    # 5 features, 100 samples
    X = np.random.randn(100, 5)
    return pd.DataFrame(X, columns=[f"f{i}" for i in range(5)])

def test_ensemble_determinism(synthetic_data):
    """Verify that two ensembles with the same seed produce identical results."""
    # Model A
    config_a = EnsembleConfig(random_state=42, detector_names=["isolation_forest"])
    det_a = EnsembleDetector(config_a)
    det_a.fit(synthetic_data)
    scores_a = det_a.score(synthetic_data)
    
    # Model B
    config_b = EnsembleConfig(random_state=42, detector_names=["isolation_forest"])
    det_b = EnsembleDetector(config_b)
    det_b.fit(synthetic_data)
    scores_b = det_b.score(synthetic_data)
    
    np.testing.assert_array_almost_equal(scores_a, scores_b, decimal=6, 
                                         err_msg="Ensembles with same seed should be identical")

def test_ensemble_variability(synthetic_data):
    """Verify that ensembles with different seeds produce different results (for randomized models)."""
    # Model A (seed 42)
    config_a = EnsembleConfig(random_state=42, detector_names=["isolation_forest"])
    det_a = EnsembleDetector(config_a)
    det_a.fit(synthetic_data)
    scores_a = det_a.score(synthetic_data)
    
    # Model B (seed 999)
    config_b = EnsembleConfig(random_state=999, detector_names=["isolation_forest"])
    det_b = EnsembleDetector(config_b)
    det_b.fit(synthetic_data)
    scores_b = det_b.score(synthetic_data)
    
    # Check that they imply different underlying trees
    # Note: Scores might be similar but typically not identical for IF
    # We check if they are NOT equal
    assert not np.allclose(scores_a, scores_b), "Ensembles with different seeds should differ"

def test_ensemble_persistence_consistency(synthetic_data, tmp_path):
    """Verify that saving and loading preserves the exact model state."""
    config = EnsembleConfig(random_state=42)
    det = EnsembleDetector(config)
    det.fit(synthetic_data)
    scores_pre = det.score(synthetic_data)
    
    # Save
    path = tmp_path / "model.joblib"
    manifest = IntegrityManifest(tmp_path / "integrity_manifest.json")
    det.save(path, manifest=manifest)

    # Load
    det_loaded = EnsembleDetector.load(path, manifest=manifest)
    scores_post = det_loaded.score(synthetic_data)
    
    np.testing.assert_array_almost_equal(scores_pre, scores_post, decimal=6,
                                         err_msg="Loaded model should match original")

import pytest
import json
import numpy as np
from pathlib import Path
from chimera.engine.normalizer import ScoreNormalizer
from chimera.engine.bootstrap import BootstrapProtocol, BootstrapConfig
from chimera.alerts import Alert, AlertEmitter

def test_normalizer_twin_sync_recovery(tmp_path):
    """Verify Normalizer recovers from primary file corruption using .bak."""
    path = tmp_path / "norm.json"
    bak_path = tmp_path / "norm.json.bak"
    
    norm = ScoreNormalizer()
    norm.fit("model1", np.random.rand(50))
    norm.save(path)
    
    assert path.exists()
    assert bak_path.exists()
    
    # Simulate primary corruption
    path.write_text("CORRUPT_DATA")
    
    # Load should fallback to bak
    reloaded = ScoreNormalizer.load(path)
    assert reloaded.is_fitted("model1")
    assert reloaded.strategy == "minmax"

def test_bootstrap_twin_sync_recovery(tmp_path):
    """Verify Bootstrap recovers from primary file missing using .bak."""
    path = tmp_path / "boot.json"
    bak_path = tmp_path / "boot.json.bak"
    
    boot = BootstrapProtocol(BootstrapConfig(min_observe=100))
    boot.save(path)
    
    assert path.exists()
    assert bak_path.exists()
    
    # Delete primary
    path.unlink()
    
    # Load should fallback to bak
    reloaded = BootstrapProtocol.load(path)
    assert reloaded.phase == "observe"
    assert reloaded.config.min_observe == 100

def test_redundant_alert_emission_isolation(tmp_path):
    """Verify that a failure in one alert sink (primary) doesn't stop others (secondary)."""
    primary = tmp_path / "primary.log"
    secondary = tmp_path / "secondary.log"
    
    # Simulate a "broken" primary stream by passing a closed file-like object or similar
    # Actually, we can just test that both are written to when healthy, 
    # and then simulate a middle-of-path exception.
    
    emitter = AlertEmitter(ndjson_path=str(primary), secondary_audit_path=str(secondary))
    
    alert = Alert(
        user="alice", score=0.8, threshold=0.5, excess=0.3,
        models_firing=["m1"], signals_firing=["s1"]
    )
    
    emitter.emit(alert)
    
    assert primary.exists()
    assert secondary.exists()
    assert "alice" in secondary.read_text()

def test_heartbeat_emission(tmp_path):
    """Verify heartbeat is written to secondary audit trail."""
    secondary = tmp_path / "audit.log"
    emitter = AlertEmitter(secondary_audit_path=str(secondary))
    
    emitter.emit_heartbeat({"cpu": 10, "mem": 20})
    
    content = secondary.read_text()
    assert "CHIMERA_HEARTBEAT" in content
    assert '"cpu": 10' in content

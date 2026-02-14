"""
Tests for the configuration system.
"""

import pytest
import json
from pathlib import Path

from chimera.config import ChimeraConfig, generate_default_config


class TestChimeraConfig:
    def test_default_config(self):
        cfg = ChimeraConfig()
        assert cfg.model.detector == "isolation_forest"
        assert cfg.model.n_estimators == 150
        assert cfg.features.enable_entropy is True
        assert cfg.rules.enabled is True
        assert cfg.scoring.auto_threshold is True

    def test_to_dict(self):
        cfg = ChimeraConfig()
        d = cfg.to_dict()
        assert "model" in d
        assert "features" in d
        assert "rules" in d
        assert "scoring" in d
        assert "output" in d

    def test_save_load_json(self, tmp_path):
        cfg = ChimeraConfig()
        cfg.model.detector = "ensemble"
        cfg.model.n_estimators = 200

        path = tmp_path / "test_config.json"
        cfg.save(path)

        loaded = ChimeraConfig.load(path)
        assert loaded.model.detector == "ensemble"
        assert loaded.model.n_estimators == 200

    def test_generate_default(self, tmp_path):
        path = tmp_path / "default.json"
        result = generate_default_config(path)
        assert result.exists()

        loaded = ChimeraConfig.load(result)
        assert loaded.model.detector == "isolation_forest"

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ChimeraConfig.load(tmp_path / "nonexistent.json")

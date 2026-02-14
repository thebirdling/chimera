"""
Configuration system for Chimera.

Provides a YAML/TOML-based configuration with sensible defaults,
section-based organization, and CLI override support.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union
import json
import logging

logger = logging.getLogger(__name__)

# Try YAML, fallback to JSON-only config
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class ModelSection:
    """Model-related configuration."""

    detector: str = "isolation_forest"
    n_estimators: int = 150
    contamination: Any = "auto"
    scaler: str = "standard"
    ensemble_strategy: str = "mean"
    ensemble_detectors: list[str] = field(
        default_factory=lambda: ["isolation_forest", "lof"]
    )


@dataclass
class FeaturesSection:
    """Feature engineering configuration."""

    max_history_days: int = 30
    enable_peer_group: bool = True
    enable_entropy: bool = True
    enable_impossible_travel: bool = True


@dataclass
class RulesSection:
    """Rule engine configuration."""

    enabled: bool = True
    load_builtins: bool = True
    custom_rules_path: Optional[str] = None
    rule_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class ScoringSection:
    """Scoring and threshold configuration."""

    auto_threshold: bool = True
    contamination: float = 0.1
    threshold: Optional[float] = None
    combine_ml_and_rules: bool = True
    rule_weight: float = 0.3  # weight of rule matches in combined score


@dataclass
class OutputSection:
    """Output and reporting configuration."""

    formats: list[str] = field(default_factory=lambda: ["json", "csv", "markdown"])
    output_dir: str = "./chimera_output"
    prefix: str = "chimera"
    include_raw_events: bool = False


@dataclass
class WatchSection:
    """File watching configuration for continuous detection."""

    poll_interval_seconds: int = 30
    pattern: str = "*.csv"
    recursive: bool = False


@dataclass
class ChimeraConfig:
    """
    Top-level Chimera configuration.

    Loaded from YAML/JSON config files, with CLI overrides.
    """

    model: ModelSection = field(default_factory=ModelSection)
    features: FeaturesSection = field(default_factory=FeaturesSection)
    rules: RulesSection = field(default_factory=RulesSection)
    scoring: ScoringSection = field(default_factory=ScoringSection)
    output: OutputSection = field(default_factory=OutputSection)
    watch: WatchSection = field(default_factory=WatchSection)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "ChimeraConfig":
        """
        Load configuration from a YAML or JSON file.

        Args:
            path: Path to the config file.

        Returns:
            Populated ChimeraConfig.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()

        if path.suffix in (".yaml", ".yml"):
            if not HAS_YAML:
                raise ImportError(
                    "PyYAML is required for YAML config files. "
                    "Install with: pip install pyyaml"
                )
            data = yaml.safe_load(raw) or {}
        elif path.suffix == ".json":
            data = json.loads(raw)
        else:
            # Try YAML first, then JSON
            try:
                if HAS_YAML:
                    data = yaml.safe_load(raw) or {}
                else:
                    data = json.loads(raw)
            except Exception:
                data = json.loads(raw)

        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "ChimeraConfig":
        config = cls()

        if "model" in data:
            for k, v in data["model"].items():
                if hasattr(config.model, k):
                    setattr(config.model, k, v)

        if "features" in data:
            for k, v in data["features"].items():
                if hasattr(config.features, k):
                    setattr(config.features, k, v)

        if "rules" in data:
            for k, v in data["rules"].items():
                if hasattr(config.rules, k):
                    setattr(config.rules, k, v)

        if "scoring" in data:
            for k, v in data["scoring"].items():
                if hasattr(config.scoring, k):
                    setattr(config.scoring, k, v)

        if "output" in data:
            for k, v in data["output"].items():
                if hasattr(config.output, k):
                    setattr(config.output, k, v)

        if "watch" in data:
            for k, v in data["watch"].items():
                if hasattr(config.watch, k):
                    setattr(config.watch, k, v)

        return config

    def save(self, path: Union[str, Path]) -> None:
        """Save configuration to a YAML or JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = self.to_dict()

        if path.suffix in (".yaml", ".yml"):
            if not HAS_YAML:
                raise ImportError("PyYAML is required for YAML output")
            with open(path, "w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

        logger.info(f"Config saved to {path}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize the entire config to a dictionary."""
        return {
            "model": {
                "detector": self.model.detector,
                "n_estimators": self.model.n_estimators,
                "contamination": self.model.contamination,
                "scaler": self.model.scaler,
                "ensemble_strategy": self.model.ensemble_strategy,
                "ensemble_detectors": self.model.ensemble_detectors,
            },
            "features": {
                "max_history_days": self.features.max_history_days,
                "enable_peer_group": self.features.enable_peer_group,
                "enable_entropy": self.features.enable_entropy,
                "enable_impossible_travel": self.features.enable_impossible_travel,
            },
            "rules": {
                "enabled": self.rules.enabled,
                "load_builtins": self.rules.load_builtins,
                "custom_rules_path": self.rules.custom_rules_path,
                "rule_overrides": self.rules.rule_overrides,
            },
            "scoring": {
                "auto_threshold": self.scoring.auto_threshold,
                "contamination": self.scoring.contamination,
                "threshold": self.scoring.threshold,
                "combine_ml_and_rules": self.scoring.combine_ml_and_rules,
                "rule_weight": self.scoring.rule_weight,
            },
            "output": {
                "formats": self.output.formats,
                "output_dir": self.output.output_dir,
                "prefix": self.output.prefix,
                "include_raw_events": self.output.include_raw_events,
            },
            "watch": {
                "poll_interval_seconds": self.watch.poll_interval_seconds,
                "pattern": self.watch.pattern,
                "recursive": self.watch.recursive,
            },
        }


def generate_default_config(path: Union[str, Path]) -> Path:
    """
    Generate a starter configuration file with documented defaults.

    Args:
        path: Output path for the config file.

    Returns:
        Path to the generated config file.
    """
    path = Path(path)
    config = ChimeraConfig()

    if path.suffix in (".yaml", ".yml") and HAS_YAML:
        header = (
            "# Chimera Configuration\n"
            "# https://github.com/thebirdling/chimera\n"
            "#\n"
            "# All settings below show their defaults.\n"
            "# Uncomment and modify as needed.\n\n"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(header)
            yaml.dump(
                config.to_dict(), f, default_flow_style=False, sort_keys=False
            )
    else:
        config.save(path)

    logger.info(f"Default config generated at {path}")
    return path

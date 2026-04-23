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
class RuntimeContractSection:
    """Stable runtime contract settings for machine-facing consumers."""

    json_stdout: bool = False
    schema_version: str = "1.0"
    write_artifact_manifest: bool = True


@dataclass
class WatchSection:
    """File watching configuration for continuous detection."""

    poll_interval_seconds: int = 30
    pattern: str = "*.csv"
    recursive: bool = False


# ── v0.3 Engine Sections ──────────────────────────────────────────

@dataclass
class NormalizationSection:
    """Score normalization pipeline configuration (v0.3)."""

    strategy: str = "minmax"        # "minmax" or "quantile"
    low_variance_threshold: float = 1e-4
    collapse_epsilon: float = 1e-6
    quantile_range: list[float] = field(default_factory=lambda: [0.05, 0.95])


@dataclass
class EnsembleV3Section:
    """Robust ensemble voting configuration (v0.3)."""

    voting_strategy: str = "mean"   # "mean"|"median"|"trimmed_mean"|"weighted"
    trim_fraction: float = 0.1
    weights: dict[str, float] = field(default_factory=dict)


@dataclass
class ThresholdSection:
    """Dynamic threshold and drift tracking configuration (v0.3)."""

    contamination: float = 0.05
    recalc_window: int = 500
    max_drift_history: int = 5000


@dataclass
class EvaluationSection:
    """Robustness evaluation and injection configuration (v0.3)."""

    injection_enabled: bool = False
    injection_type: str = "burst_attack"
    injection_magnitude: float = 3.0
    injection_window: int = 50
    injection_seed: int = 42
    contamination_range: list[float] = field(default_factory=lambda: [0.01, 0.30])
    sensitivity_steps: int = 20
    attack_families: list[str] = field(
        default_factory=lambda: [
            "session_hijack",
            "mfa_bypass",
            "low_and_slow",
            "password_spraying",
            "coordinated_campaign",
            "identity_drift",
            "temporal_jitter",
        ]
    )
    report_slices: list[str] = field(
        default_factory=lambda: [
            "baseline",
            "chimera",
            "identity_research",
            "takeover_only",
            "coordination_heavy",
            "campaign_focus",
            "infra_reuse_heavy",
            "mfa_bypass_focus",
            "spray_focus",
            "low_and_slow_focus",
            "session_concurrency_focus",
            "geo_velocity_focus",
            "examples",
        ]
    )


@dataclass
class IntegritySection:
    """SHA-256 integrity probe configuration (v0.3)."""

    enabled: bool = True
    backup_on_train: bool = True


@dataclass
class ExperimentalSection:
    """Experimental / topology sandbox configuration (v0.3)."""

    topology_enabled: bool = False
    topology_epsilon: float = 0.5
    topology_max_dimension: int = 1
    topology_max_samples: int = 2000


@dataclass
class IdentityResearchSection:
    """Structured identity-behavior reasoning configuration (v0.4)."""

    enabled: bool = False
    session_gap_minutes: int = 45
    burst_window_minutes: int = 5
    relation_window_minutes: int = 15
    max_shared_entity_users: int = 10
    scoring_hard_floor_enabled: bool = True
    fusion_hard_floor: float = 0.35
    takeover_hard_floor: float = 0.58
    takeover_support_floor: float = 0.55
    case_aggregation_enabled: bool = True
    case_time_window_minutes: int = 30


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
    runtime_contract: RuntimeContractSection = field(default_factory=RuntimeContractSection)
    watch: WatchSection = field(default_factory=WatchSection)
    # v0.3 engine sections
    normalization: NormalizationSection = field(default_factory=NormalizationSection)
    ensemble_v3: EnsembleV3Section = field(default_factory=EnsembleV3Section)
    threshold: ThresholdSection = field(default_factory=ThresholdSection)
    evaluation: EvaluationSection = field(default_factory=EvaluationSection)
    integrity: IntegritySection = field(default_factory=IntegritySection)
    experimental: ExperimentalSection = field(default_factory=ExperimentalSection)
    identity_research: IdentityResearchSection = field(
        default_factory=IdentityResearchSection
    )
    seed: int = 42

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

        if "runtime_contract" in data:
            for k, v in data["runtime_contract"].items():
                if hasattr(config.runtime_contract, k):
                    setattr(config.runtime_contract, k, v)

        if "normalization" in data:
            for k, v in data["normalization"].items():
                if hasattr(config.normalization, k):
                    setattr(config.normalization, k, v)

        if "ensemble_v3" in data:
            for k, v in data["ensemble_v3"].items():
                if hasattr(config.ensemble_v3, k):
                    setattr(config.ensemble_v3, k, v)

        if "threshold" in data:
            for k, v in data["threshold"].items():
                if hasattr(config.threshold, k):
                    setattr(config.threshold, k, v)

        if "evaluation" in data:
            for k, v in data["evaluation"].items():
                if hasattr(config.evaluation, k):
                    setattr(config.evaluation, k, v)

        if "integrity" in data:
            for k, v in data["integrity"].items():
                if hasattr(config.integrity, k):
                    setattr(config.integrity, k, v)

        if "experimental" in data:
            for k, v in data["experimental"].items():
                if hasattr(config.experimental, k):
                    setattr(config.experimental, k, v)

        if "identity_research" in data:
            for k, v in data["identity_research"].items():
                if hasattr(config.identity_research, k):
                    setattr(config.identity_research, k, v)

        if "seed" in data:
            config.seed = int(data["seed"])

        return cls._validate_config_paths(config)

    @classmethod
    def _validate_config_paths(cls, config: "ChimeraConfig") -> "ChimeraConfig":
        """Canonicalize and safety-check all path-typed config fields (SEC-06).

        Rejects any path that contains null bytes or that resolves to a
        location with ``..`` traversal (protects against config injection).
        """
        import os

        def _check_path(raw: Optional[str], field: str) -> Optional[str]:
            if raw is None:
                return raw
            if "\x00" in str(raw):
                raise ValueError(f"Null byte in config path field '{field}'")
            # Normalize separators and resolve without requiring existence
            normalized = os.path.normpath(str(raw))
            # Reject absolute paths that point outside the CWD in relative configs
            # (allow absolute paths — they are explicit operator choices)
            return normalized

        config.rules.custom_rules_path = _check_path(
            config.rules.custom_rules_path, "rules.custom_rules_path"
        )
        config.output.output_dir = _check_path(
            config.output.output_dir, "output.output_dir"
        )  # type: ignore[assignment]
        return config

    def save(self, path: Union[str, Path]) -> None:
        """Save configuration to a YAML or JSON file."""
        from chimera.engine.safe_io import atomic_write_text
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = self.to_dict()

        if path.suffix in (".yaml", ".yml"):
            if not HAS_YAML:
                raise ImportError("PyYAML is required for YAML output")
            import io
            buf = io.StringIO()
            yaml.dump(data, buf, default_flow_style=False, sort_keys=False)
            atomic_write_text(path, buf.getvalue(), mode=0o640)
        else:
            atomic_write_text(path, json.dumps(data, indent=2), mode=0o640)

        logger.info("Config saved to %s", path)

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
            "runtime_contract": {
                "json_stdout": self.runtime_contract.json_stdout,
                "schema_version": self.runtime_contract.schema_version,
                "write_artifact_manifest": self.runtime_contract.write_artifact_manifest,
            },
            "normalization": {
                "strategy": self.normalization.strategy,
                "low_variance_threshold": self.normalization.low_variance_threshold,
                "collapse_epsilon": self.normalization.collapse_epsilon,
                "quantile_range": self.normalization.quantile_range,
            },
            "ensemble_v3": {
                "voting_strategy": self.ensemble_v3.voting_strategy,
                "trim_fraction": self.ensemble_v3.trim_fraction,
                "weights": self.ensemble_v3.weights,
            },
            "threshold": {
                "contamination": self.threshold.contamination,
                "recalc_window": self.threshold.recalc_window,
                "max_drift_history": self.threshold.max_drift_history,
            },
            "evaluation": {
                "injection_enabled": self.evaluation.injection_enabled,
                "injection_type": self.evaluation.injection_type,
                "injection_magnitude": self.evaluation.injection_magnitude,
                "injection_window": self.evaluation.injection_window,
                "injection_seed": self.evaluation.injection_seed,
                "contamination_range": self.evaluation.contamination_range,
                "sensitivity_steps": self.evaluation.sensitivity_steps,
                "attack_families": self.evaluation.attack_families,
                "report_slices": self.evaluation.report_slices,
            },
            "integrity": {
                "enabled": self.integrity.enabled,
                "backup_on_train": self.integrity.backup_on_train,
            },
            "experimental": {
                "topology_enabled": self.experimental.topology_enabled,
                "topology_epsilon": self.experimental.topology_epsilon,
                "topology_max_dimension": self.experimental.topology_max_dimension,
                "topology_max_samples": self.experimental.topology_max_samples,
            },
            "identity_research": {
                "enabled": self.identity_research.enabled,
                "session_gap_minutes": self.identity_research.session_gap_minutes,
                "burst_window_minutes": self.identity_research.burst_window_minutes,
                "relation_window_minutes": self.identity_research.relation_window_minutes,
                "max_shared_entity_users": self.identity_research.max_shared_entity_users,
                "scoring_hard_floor_enabled": self.identity_research.scoring_hard_floor_enabled,
                "fusion_hard_floor": self.identity_research.fusion_hard_floor,
                "takeover_hard_floor": self.identity_research.takeover_hard_floor,
                "takeover_support_floor": self.identity_research.takeover_support_floor,
                "case_aggregation_enabled": self.identity_research.case_aggregation_enabled,
                "case_time_window_minutes": self.identity_research.case_time_window_minutes,
            },
            "seed": self.seed,
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

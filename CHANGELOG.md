# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-04-15

### Added

- **Campaign-aware identity features**: added deterministic password-spraying, low-and-slow, and fused campaign scores to the identity research layer.
- **Ordered takeover kernel**: new Rust and Python-fallback temporal kernel for login -> session continuation -> privileged-action progression, exposed as `identity_takeover_sequence_score`.
- **Benchmark markdown reporting**: `chimera bench` and LANL suite runs now emit paper-style Markdown summaries alongside JSON reports.
- **Campaign rules**: built-in `password_spraying` and `low_and_slow_campaign` rules for deterministic comparison against the identity graph layer.
- **Verified model loading**: CLI and library load paths now require integrity verification by default instead of silently accepting unsigned joblib artifacts.

### Changed

- **Release versioning**: project metadata and runtime version are aligned at `0.5.0`.
- **Benchmark slices**: evaluation defaults now include `campaign_focus`, `spray_focus`, and `low_and_slow_focus`.
- **Research positioning**: README and docs now describe Chimera as progressing from robust anomaly scoring toward structured identity-behavior and campaign reasoning.

## [0.4.0] - 2026-04-13

### Added

- **Identity research subsystem**: new `chimera/identity.py` module for deterministic sequence and relationship reasoning over authentication behavior.
- **Identity research features**: session cadence, inter-event rhythm deviation, suspicious country transitions, shared IP/device/ASN concentration, synchronized peer activity, and fused identity risk signals.
- **Identity-aware reporting**: event outputs and generated reports now carry identity research signals and human-readable reasons when the layer is enabled.
- **Research system map**: added `docs/Research_System_Map.md` to capture subsystem roles, Antigravity artifact history, completed hardening work, and open research gaps.
- **Expanded identity attack injection**: benchmark injector now supports `session_hijack`, `low_and_slow`, `password_spraying`, `coordinated_campaign`, `identity_drift`, and `temporal_jitter`.

### Changed

- **Configuration model**: `chimera/config.py` now round-trips engine, evaluation, experimental, and identity research sections instead of only legacy top-level sections.
- **CLI benchmark semantics**: `chimera bench` now scores injected test events rather than pre-injection score arrays, so reported ground truth aligns with evaluated data.
- **Default config reference**: `chimera.yaml` now reflects the identity-centric research phase and includes attack-family/report-slice settings.
- **Project positioning**: README and docs now consistently describe Chimera as offline-first, identity-focused, adversarially robust, research-grade, and reproducible.

## [0.3.0] - 2026-02-24

### Added

- **`chimera/engine/` — Core Robustness Engine**: `normalizer.py`, `voter.py`, `threshold.py`, `pipeline.py`, `integrity.py`, `temporal.py`, `streaming.py`.
- **Contamination-stable Score Normalization** (`normalizer.py`): MinMax and quantile projection with three guards — collapse detection, low-variance guard, and insufficient-data guard.
- **Ensemble Voter** (`voter.py`): Four strategies (mean / median / trimmed mean / weighted) plus inter-model disagreement entropy H(X_t) and score variance as first-class robustness diagnostics.
- **Dynamic Threshold Engine** (`threshold.py`): Contamination-percentile τ with per-update drift tracking Δτ and instability metric exposed via `ScoreResult`.
- **`EnginePipeline`** (`pipeline.py`): Orchestrates normalizer → voter → threshold; `fit()` / `score()` / `save()` / `load()` / `from_config()` API.
- **SHA-256 Integrity Probes** (`integrity.py`): Atomic manifest write + backup-on-train for model and config files (the Roman Concrete self-healing protocol).
- **Fourier Cyclic Temporal Features + von Mises Baseline** (`temporal.py`): `encode_hour_cyclic()` / `encode_dow_cyclic()` / `encode_month_cyclic()` and per-user `VonMisesBaseline` (circular analog of Gaussian — the Antikythera temporal vectoring protocol).
- **Clepsydra Streaming Buffer** (`streaming.py`): Thread-safe ring buffer with threshold-triggered and timeout-triggered batch release for continuous log ingestion.
- **`chimera/evaluation/` — Robustness Evaluation**: `injector.py` (5 deterministic injection types), `metrics.py` (`RobustnessReport` with drift / entropy / variance / sensitivity curve / DR@FPR), `runner.py` (baseline vs Chimera benchmark).
- **`chimera/experimental/topology.py` — TDA Sandbox**: Vietoris-Rips persistent homology (Betti-0/1) via `gudhi` + Gower distance + Mahalanobis anomaly score. Feature-flagged; gracefully disabled without `gudhi`.
- **`chimera/_native/` — C Extension**: `distances.c` (CBLAS Gram matrix trick for O(n²) LOF distance), cffi/ctypes loader with numpy fallback, and `build.py` with CBLAS auto-detection (the Vedic Matrix optimization protocol).
- **CLI `chimera run`**: Full v0.3 pipeline from config file — loads config → engineers features → scores with all detectors → normalizes → votes → applies dynamic threshold → writes JSON report.
- **CLI `chimera bench`**: Baseline-vs-Chimera robustness benchmark with synthetic anomaly injection and side-by-side metric table.
- **`chimera.yaml`**: Full annotated default configuration covering all v0.3 parameters.
- **`tests/test_engine.py`**: Formal pytest suite with 30+ test cases (normalizer, voter, threshold, pipeline, temporal, streaming buffer, injection, robustness metrics).

### Changed

- **`chimera/config.py`**: Extended with six new dataclass sections: `NormalizationSection`, `EnsembleV3Section`, `ThresholdSection`, `EvaluationSection`, `IntegritySection`, `ExperimentalSection`.

## [0.2.0] - 2026-02-14

### Added

- **Ensemble Detection**: Robust voting mechanism combining Isolation Forest and LOF with MinMax score normalization.
- **Dynamic Thresholding**: Anomaly thresholds are now calculated dynamically based on the contamination percentile of the ensemble score distribution.
- **Threat Intelligence**: New `chimera.threat_intel` module for offline integration of IP/ASN blocklists.
- **Feature Engineering**: Added entropy-based features (Shannon entropy of IP/Country distributions) and peer-group velocity deviations.
- **Research Documentation**: specific `docs/Chimera_Research_Brief.md` detailing the architectural decisions.
- **Security Policy**: Added `SECURITY.md` defining offline-first guarantees.

### Changed

- **Core Architecture**: Introduced `DetectorRegistry` for cleaner model plugin management.
- **Determinism**: Enforced strict random seeding across all ML components to ensure reproducibility.
- **Type Safety**: comprehensive type hints added to `scoring.py`, `detectors`, and public APIs.

### Fixed

- **Magic Numbers**: Extracted hardcoded risk thresholds into named constants in `AnomalyScorer`.
- **Ensemble Randomness**: Fixed bug where `random_state` was not propagated to sub-detectors in the ensemble.

## [0.1.0] - 2026-02-08

### Added

- Initial release.
- Basic CLI structure.
- Isolation Forest detector.
- Simple rule engine.

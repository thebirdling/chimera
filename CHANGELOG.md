# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

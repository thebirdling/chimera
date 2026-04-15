# Chimera: Identity-Centric Behavioral Research Framework

Chimera is an offline-first framework for studying authentication and identity behavior under adversarial and infrastructure constraints. It combines unsupervised detectors, deterministic threat rules, a robustness-first ensemble engine, and a structured identity research layer for sequence and relationship reasoning.

Chimera is a research artifact, not a production SIEM. The project is designed for controlled analysis, reproducible experimentation, and publishable security research in local or air-gapped environments.

## Research Direction

- Offline-first: all core workflows run locally without live enrichment dependencies.
- Identity-focused: current work centers on authentication, sessions, and coordinated account abuse.
- Adversarially robust: persistence, integrity, and evaluation are treated as core research concerns.
- Reproducible: deterministic seeds, synthetic attack injection, and benchmark reporting are first-class.

## System Overview

Chimera currently includes:

- Local ingestion into a canonical `AuthEvent` schema.
- Behavioral feature engineering for temporal, velocity, geography, device, session, entropy, and peer-group signals.
- Detector layer with Isolation Forest, LOF, and ensemble support.
- Robustness engine for score normalization, voting, dynamic thresholding, threshold drift, and temporal baselines.
- Identity research layer for session cadence, inter-event rhythm, geography transitions, shared IP/device reasoning, synchronized peers, campaign heuristics, and ordered takeover progression.
- Evaluation harness for deterministic identity-attack injection and robustness benchmarking.
- Paper-style benchmark reporting for publishable offline experiments.
- Optional topology sandbox and native acceleration path.
- Verified model loading via integrity manifests, with the CLI refusing unsigned model artifacts by default.

See [Research System Map](docs/Research_System_Map.md) for the current subsystem map, thesis evolution, and open research gaps.

## Quick Start

```bash
pip install -e .
chimera init -o chimera.yaml
chimera run --config chimera.yaml --input auth.csv --output ./chimera_output
chimera bench --config chimera.yaml --input auth.csv --injection-type session_hijack
```

## Current Identity Research Layer

The current phase adds deterministic, additive research signals:

- per-user session/sequence modeling
- burst and temporal-regularity analysis
- suspicious country-transition flags
- shared IP, shared device, and ASN concentration
- synchronized multi-user local activity
- password-spraying and low-and-slow campaign heuristics
- ordered takeover sequence progression from login to token reuse to privileged follow-on activity
- research-grade benchmark markdown reports for single runs and LANL suite summaries

These signals are designed to plug into the existing engine pipeline as additional channels rather than replace the current detectors.

## Notes

- The project remains focused on authentication and identity behavior; broad telemetry expansion is intentionally deferred.
- The current identity layer is feature-driven and deterministic. Deep sequence models and heavyweight graph infrastructure remain out of scope for now.
- Native Rust kernels now accelerate shared-entity burst counting and ordered takeover sequence progression, with Python fallbacks preserved for default installs.
- Experimental topology remains optional and comparative.

## License

MIT

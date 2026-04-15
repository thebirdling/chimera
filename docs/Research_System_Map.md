# Chimera Research System Map

Chimera is an offline-first, identity-focused, adversarially robust research framework for behavioral anomaly detection. The project has evolved from a modular auth-log detector into a broader research platform for studying how identity behavior can be modeled under constrained infrastructure, zero network egress, and active adversarial pressure.

## Current System Map

### Implemented Subsystems

- `data_loader.py`: canonical authentication-event schema and local CSV/JSON ingestion.
- `feature_engineering.py`: behavioral vectors for temporal, velocity, geography, device, session, auth, entropy, peer-group, and identity-research signals.
- `detectors/`: unsupervised detector layer for Isolation Forest, LOF, and ensemble wiring.
- `engine/`: robustness core with normalization, voting, thresholding, temporal modeling, streaming, bootstrap state, integrity checks, and safe I/O.
- `suppression.py` and `triage.py`: false-positive reduction and ONNX-backed triage experiments.
- `fleet_monitor.py` and `correlator.py`: cross-user coordination and cluster-level reasoning.
- `evaluation/`: synthetic attack injection, robustness metrics, and benchmark runner.
- `experimental/topology.py`: optional topological anomaly sandbox.
- `_native/`: native acceleration path for distance-heavy workloads.

### New Identity Research Layer

The current phase adds structured identity-behavior reasoning:

- Per-user sequence modeling with deterministic session boundaries.
- Short-range temporal rhythm and burst analysis.
- Geography-transition flags for suspicious location changes.
- Local relationship signals for shared IPs, shared devices, ASN concentration, synchronized peer activity, and fan-out behavior.
- Campaign-oriented identity heuristics for password spraying, low-and-slow credential abuse, and coordinated cross-account infrastructure reuse.
- Ordered takeover progression from login establishment through token reuse into privileged follow-on actions.
- Additive fusion of identity sequence and relationship scores into the engine pipeline.

## Artifact History Distilled

### Thesis Evolution

- Early artifacts centered on modular auth-log anomaly detection in air-gapped settings.
- Mid-phase artifacts introduced robustness primitives: normalization, dynamic thresholding, temporal baselines, streaming, and integrity.
- Later Antigravity walkthroughs shifted the thesis toward adversarial hardening, encrypted persistence, and resilient offline operation.
- The present phase extends that thesis from pointwise anomaly scoring toward structured identity-behavior reasoning.

### Completed Hardening Work

- Integrity manifest and safe deserialization path.
- Secure persistence and encrypted NDJSON logging.
- Bootstrap hardening, drift guard, suppression floor, and fleet monitoring.
- Robustness evaluation harness and adversarial regression suites.

### Downgraded or Deferred Ideas

- Broad telemetry generalization beyond authentication remains deferred.
- Heavy graph infrastructure and deep sequence models remain intentionally out of scope.
- Topological analysis remains optional and comparative, not a mandatory core path.

## Evidence vs Open Claims

### Supported by Code and Tests

- Offline, reproducible auth-log analysis.
- Robust score normalization and dynamic thresholding.
- Adversarial hardening primitives and encrypted forensic persistence.
- Deterministic identity sequence and relationship signals.
- Deterministic campaign heuristics and ordered takeover reasoning with Rust-accelerated kernels and Python fallbacks.
- Synthetic identity-attack injection families and benchmark reporting.
- Paper-style benchmark reports suitable for research review and release artifacts.

### Still Requiring Stronger Evidence

- Claims of superiority over alternative UEBA approaches beyond synthetic evaluation.
- Generalization of identity signals across heterogeneous organizations or telemetry domains.
- Quantified research advantage from topology relative to sequence and relationship reasoning.

## Open Research Gaps

- Better longitudinal baselines for sparse or brand-new identities.
- Richer session-hijack and identity-drift injection grounded in real enterprise traces.
- Comparative ablations between detector-only, detector-plus-identity, and topology-assisted fusion.
- Wider real-world dataset validation and publication-grade evaluation tables beyond synthetic and LANL-style slices.

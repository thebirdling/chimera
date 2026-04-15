# Chimera: Identity-Centric Behavioral Research Framework

![Open Graph, Homepage (1)](https://cdn.thebirdling.com/github/images/chimera-v5-git-cover.png)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status: Research Prototype](https://img.shields.io/badge/Status-Research%20Prototype-orange.svg)](CONTRIBUTING.md)
[![Release: v0.5.1](https://img.shields.io/badge/release-v0.5.1-black.svg)](CHANGELOG.md)
[![Focus: Offline First](https://img.shields.io/badge/focus-offline--first-1b7f5a.svg)](docs/Research_System_Map.md)
[![Focus: Identity Research](https://img.shields.io/badge/focus-identity--behavior-7b2cbf.svg)](docs/Chimera_Research_Brief.md)

Chimera is an offline-first, identity-focused, adversarially robust research framework for studying authentication and account behavior under infrastructure constraints. It combines unsupervised detectors, deterministic threat rules, a robustness-first scoring engine, and a structured identity reasoning layer for sessions, sequences, campaigns, and coordinated attack patterns.

Chimera is built as a research-grade system first. The goal is not to masquerade as a full cloud SIEM, but to provide a reproducible, explainable platform for identity-behavior anomaly research in local, forensic, constrained, and air-gapped environments.

## Why Chimera Exists

Most modern detection stacks assume:

- cloud enrichment is available
- telemetry volume is effectively unlimited
- internet-connected control planes are acceptable
- operational convenience matters more than reproducibility

Chimera starts from the opposite premise:

- core workflows should run offline
- identity and authentication behavior deserve first-class modeling
- adversarial robustness is part of the system, not a later bolt-on
- research claims should be testable, benchmarkable, and explainable

That makes Chimera a strong fit for:

- identity-centric cybersecurity research
- air-gapped or tightly controlled environments
- reproducible benchmark work
- local threat modeling and detector ablations
- adversarial evaluation of account takeover and abuse patterns

## Architecture Overview

Chimera currently consists of the following major layers:

| Layer | Purpose |
| --- | --- |
| `data_loader.py` | Canonical authentication-event ingestion from local CSV, JSON, and LANL-style auth logs |
| `feature_engineering.py` | Temporal, geography, device, session, entropy, peer-group, and identity-research features |
| `detectors/` | Unsupervised detectors including Isolation Forest, LOF, and registry-driven extensions |
| `engine/` | Robust score normalization, voting, dynamic thresholding, temporal drift handling, integrity, and persistence |
| `identity.py` | Deterministic sequence, session, graph, campaign, and takeover progression reasoning |
| `rules/` | Human-readable deterministic detection rules for analyst-comparable logic |
| `evaluation/` | Synthetic attack injection, benchmark runner, robustness metrics, and report generation |
| `reporting.py` | JSON and Markdown benchmark/report artifacts for analysis and publication workflows |
| `_native/` + `rust/graph_kernels/` | Optional native acceleration for relationship and ordered-attack kernels |

See the detailed docs for a full subsystem map:

- [Research System Map](docs/Research_System_Map.md)
- [Architecture Overview](docs/Architecture_Overview.md)
- [Evaluation Playbook](docs/Evaluation_Playbook.md)
- [CLI and Output Guide](docs/CLI_and_Outputs.md)

## Research Direction

Chimera v0.5.1 continues the project shift from robust anomaly scoring toward structured identity-behavior reasoning.

Current emphasis:

- offline-first execution
- identity-focused behavioral modeling
- adversarially robust local operation
- deterministic synthetic attack evaluation
- explainable event-level reasoning
- publishable benchmark artifacts

## Current Identity Research Layer

The current release includes additive research signals that join the existing engine pipeline without replacing baseline detectors:

- per-user session and sequence modeling
- short-range temporal rhythm and burst analysis
- suspicious geography transition detection
- shared IP, shared device, and ASN concentration features
- synchronized peer activity and local coordination signals
- password-spraying and low-and-slow campaign heuristics
- ordered takeover progression from login to token reuse to privileged follow-on actions
- analyst-readable identity reasons attached to benchmark and runtime outputs

These are implemented as deterministic, feature-driven components so they remain testable, reproducible, and practical under constrained infrastructure.

## CLI Experience

Chimera now presents a stronger command-line identity during runtime:

- branded ASCII startup banners
- lightweight loading animations for key run paths
- clearer command headers for `run`, `bench`, `bench-lanl`, `train`, `detect`, and other operational flows
- Markdown benchmark reports alongside JSON artifacts for easier review and release preparation

## Quick Start

```bash
pip install -e .
chimera init -o chimera.yaml
chimera run --config chimera.yaml --input auth.csv --output ./chimera_output
chimera bench --config chimera.yaml --input auth.csv --injection-type session_hijack
chimera bench-lanl --config chimera.yaml --input auth.txt --limit 50000
```

## Example Workflows

Train a local detector:

```bash
chimera train auth.csv --output ./models/chimera_model.joblib
```

Run the full engine pipeline:

```bash
chimera run --config chimera.yaml --input auth.csv --output ./chimera_output
```

Benchmark identity attacks:

```bash
chimera bench --config chimera.yaml --input auth.csv --injection-type password_spraying
chimera bench --config chimera.yaml --input auth.csv --injection-type session_hijack
```

Generate a LANL-style research suite:

```bash
python scripts/run_lanl_benchmark.py --config chimera.yaml --input auth.txt --preset publishable_identity
```

## Evaluation Story

Chimera is structured to benchmark identity-centric attack hypotheses, not just produce pointwise anomaly scores.

Current evaluation support includes:

- session hijack patterns
- MFA bypass style identity drift
- password spraying and credential stuffing
- low-and-slow credential abuse
- synchronized multi-account campaigns
- temporal jitter intended to evade naive windows

Generated reports emphasize:

- detection lift
- false-positive behavior
- threshold stability
- robustness under contamination shift
- explainability examples for representative findings

## Security Model

Chimera is designed as a controlled offline research platform.

Key release hardening points:

- integrity-verified model loading is required by default
- benchmark outputs are local and reproducible
- optional native acceleration preserves Python fallbacks
- no external graph or enrichment service is required for core identity reasoning

Important boundary:

- Chimera is suitable for controlled research and local deployment
- Chimera is not positioned as a public multi-tenant internet-facing detection service

## Supported By

<a href="https://thebirdling.com">
  <img src="https://assets.basehub.com/38638add/2ae033578930cf8dad65a3e4d01d20b1/basehub-tb-logo-rect-light.svg" alt="The Birdling" width="200" />
</a>

Chimera is maintained and deployed by **The Birdling**'s SPE (Special Projects Engineering) team.

## Documentation

- [Research System Map](docs/Research_System_Map.md)
- [Chimera Research Brief](docs/Chimera_Research_Brief.md)
- [Architecture Overview](docs/Architecture_Overview.md)
- [Evaluation Playbook](docs/Evaluation_Playbook.md)
- [CLI and Output Guide](docs/CLI_and_Outputs.md)
- [Repo Transplant Shortlist](docs/Repo_Transplant_Shortlist.md)
- [Changelog](CHANGELOG.md)

## Notes

- The project remains intentionally focused on authentication and identity behavior.
- Deep learning and heavyweight graph infrastructure remain out of scope for the core release path.
- Rust acceleration is optional and degrades gracefully.
- Experimental topology remains comparative, not foundational.

## License

MIT

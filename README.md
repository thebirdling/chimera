# Chimera: Portable Identity-Centric Behavioral Research Runtime

![Open Graph, Homepage (1)](https://cdn.thebirdling.com/github/images/chimera-v5-git-cover.png)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status: Research Prototype](https://img.shields.io/badge/Status-Research%20Prototype-orange.svg)](CONTRIBUTING.md)
[![Release: v0.6.0](https://img.shields.io/badge/release-v0.6.0-black.svg)](CHANGELOG.md)
[![Focus: Offline First](https://img.shields.io/badge/focus-offline--first-1b7f5a.svg)](docs/Research_System_Map.md)
[![Focus: Identity Research](https://img.shields.io/badge/focus-identity--behavior-7b2cbf.svg)](docs/Chimera_Research_Brief.md)
[![Focus: Portable Runtime](https://img.shields.io/badge/focus-portable--runtime-2d6cdf.svg)](docs/Embedding_Chimera.md)

Chimera is an offline-first, identity-focused, adversarially robust research framework for studying authentication and account behavior under infrastructure constraints. It combines unsupervised detectors, deterministic threat rules, a robustness-first scoring engine, structured identity reasoning, and now a portable runtime contract designed to support embedding and wrapper-based distribution.

Chimera remains a research-grade system first. The goal is not to imitate a cloud SIEM, but to provide a reproducible, explainable platform for identity-behavior anomaly research in local, forensic, constrained, and air-gapped environments.

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

## What’s New in v0.6.0

`v0.6.0` is the portable runtime release before the first `npm`/`npx` distribution milestone.

Key additions:

- stable machine-facing JSON envelopes for major commands
- `artifact_manifest.json` output directories for wrapper discovery
- programmatic API for `run_pipeline`, `run_benchmark`, `inspect_model`, and `doctor`
- deterministic offline `agent-review` for local analyst-style triage
- case-level identity reasoning through deterministic `IdentityCase` aggregation
- `chimera doctor` for runtime diagnostics
- install, embedding, and schema documentation for the pre-npm bridge

This means the next npm release can treat Python Chimera as the source-of-truth runtime instead of forcing a rewrite or scraping terminal output.

## Architecture Overview

Chimera currently consists of the following major layers:

| Layer | Purpose |
| --- | --- |
| `data_loader.py` | Canonical authentication-event ingestion from local CSV, JSON, and LANL-style auth logs |
| `feature_engineering.py` | Temporal, geography, device, session, entropy, peer-group, and identity-research features |
| `detectors/` | Unsupervised detectors including Isolation Forest, LOF, and registry-driven extensions |
| `engine/` | Robust score normalization, voting, dynamic thresholding, temporal drift handling, integrity, and persistence |
| `identity.py` | Deterministic sequence, session, graph, campaign, and takeover progression reasoning |
| `cases.py` | Deterministic case-level grouping for takeover, spray, low-and-slow, and coordinated identity campaigns |
| `api.py` + `contracts.py` | Stable portable runtime API and machine-facing output contracts |
| `rules/` | Human-readable deterministic detection rules for analyst-comparable logic |
| `evaluation/` | Synthetic attack injection, benchmark runner, robustness metrics, and report generation |
| `reporting.py` | JSON and Markdown benchmark/report artifacts for analysis and publication workflows |
| `_native/` + `rust/graph_kernels/` | Optional native acceleration for relationship and ordered-attack kernels |

See the detailed docs for a full subsystem map:

- [Research System Map](docs/Research_System_Map.md)
- [Architecture Overview](docs/Architecture_Overview.md)
- [Evaluation Playbook](docs/Evaluation_Playbook.md)
- [CLI and Output Guide](docs/CLI_and_Outputs.md)
- [Embedding Chimera](docs/Embedding_Chimera.md)
- [Output Schemas](docs/Output_Schemas.md)

## Research Direction

Chimera v0.6.0 continues the project shift from robust anomaly scoring toward structured identity-behavior reasoning.

Current emphasis:

- offline-first execution
- identity-focused behavioral modeling
- adversarially robust local operation
- deterministic synthetic attack evaluation
- explainable event-level and case-level reasoning
- publishable benchmark artifacts
- portable runtime contracts for future wrapper distribution

## Current Identity Research Layer

The current release includes additive research signals that join the existing engine pipeline without replacing baseline detectors:

- per-user session and sequence modeling
- short-range temporal rhythm and burst analysis
- suspicious geography transition detection
- shared IP, shared device, and ASN concentration features
- synchronized peer activity and local coordination signals
- password-spraying and low-and-slow campaign heuristics
- ordered takeover progression from login to token reuse to privileged follow-on actions
- case-level aggregation into reviewable `IdentityCase` objects
- analyst-readable identity reasons attached to benchmark and runtime outputs

These are implemented as deterministic, feature-driven components so they remain testable, reproducible, and practical under constrained infrastructure.

## Portable Runtime Contract

`v0.6.0` introduces the stable machine-facing layer that future wrappers will depend on.

Major commands now support `--json` for a versioned stdout envelope:

- `chimera run --json`
- `chimera detect --json`
- `chimera bench --json`
- `chimera bench-lanl --json`
- `chimera info --json`
- `chimera doctor --json`
- `chimera agent-review --input ./chimera_output --json`

Output directories now also emit `artifact_manifest.json` so external tooling can discover generated files without brittle path assumptions.

## CLI Experience

Chimera retains its stronger command-line identity during runtime:

- branded ASCII startup banners
- lightweight loading animations for key run paths
- clearer command headers for `run`, `bench`, `bench-lanl`, `train`, `detect`, `doctor`, and related flows
- Markdown benchmark reports alongside stable JSON envelopes

## Quick Start

```bash
pip install -e .
chimera init -o chimera.yaml
chimera doctor
chimera run --config chimera.yaml --input auth.csv --output ./chimera_output
chimera bench --config chimera.yaml --input auth.csv --injection-type session_hijack
```

For a CLI-first install path:

```bash
pipx install .
chimera doctor --json
```

## Example Workflows

Train a verified local detector:

```bash
chimera train auth.csv --output ./models/chimera_model.joblib
```

Run the full engine pipeline with stable JSON:

```bash
chimera run --config chimera.yaml --input auth.csv --output ./chimera_output --json
```

Detect with a trained model and emit wrapper-friendly output:

```bash
chimera detect auth.csv ./models/chimera_model.joblib --output detect_results.json --json
```

Generate a deterministic offline analyst review from a Chimera artifact:

```bash
chimera agent-review --input ./chimera_output --output ./chimera_agent_review --json
```

Benchmark identity attacks:

```bash
chimera bench --config chimera.yaml --input auth.csv --injection-type password_spraying --json
chimera bench --config chimera.yaml --input auth.csv --injection-type session_hijack --json
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
- case-level detection summaries

## Security Model

Chimera is designed as a controlled offline research platform.

Key release hardening points:

- integrity-verified model loading is required by default
- benchmark outputs are local and reproducible
- optional native acceleration preserves Python fallbacks
- optional native-kernel absence is treated as healthy fallback behavior, not a failed install
- `agent-review` rejects oversized artifacts and ignores manifest paths that escape the artifact directory
- native library loading is restricted to expected Chimera kernel names rather than arbitrary wildcard matches
- no external graph or enrichment service is required for core identity reasoning
- the portable runtime contract does not bypass verified model loading

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
- [Embedding Chimera](docs/Embedding_Chimera.md)
- [Output Schemas](docs/Output_Schemas.md)
- [Install and Smoke Test](docs/Install_and_Smoke_Test.md)
- [Repo Transplant Shortlist](docs/Repo_Transplant_Shortlist.md)
- [Changelog](CHANGELOG.md)

## Notes

- The project remains intentionally focused on authentication and identity behavior.
- Deep learning and heavyweight graph infrastructure remain out of scope for the core release path.
- Rust acceleration is optional and degrades gracefully.
- `v0.6.0` is the pre-npm release; the first actual npm/npx distribution should land in `v0.7.0`.

## License

MIT

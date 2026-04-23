# Chimera CLI and Output Guide

This document explains what Chimera’s main CLI commands do, what they produce, and how to interpret the resulting artifacts.

## 1. CLI Design Goals

The CLI is intended to feel:

- local-first
- research-oriented
- explainable
- consistent across training, scoring, and benchmarking

In v0.6.0 the CLI also has stronger presentation:

- branded ASCII startup banners
- lightweight loading animations
- clearer stage transitions during longer workflows
- package-friendly JSON mode that keeps machine output on stdout and live presentation on stderr

## 2. Core Commands

### 2.1 `chimera init`

Purpose:

- generate a starter configuration file

Typical usage:

```bash
chimera init -o chimera.yaml
```

### 2.2 `chimera train`

Purpose:

- train a baseline detector on local auth data

Typical usage:

```bash
chimera train auth.csv --output ./models/chimera_model.joblib
```

Output expectations:

- model artifact
- metadata sidecar
- integrity manifest when enabled

### 2.3 `chimera detect`

Purpose:

- load a verified detector
- score local auth data
- optionally run rules

Typical usage:

```bash
chimera detect auth.csv ./models/chimera_model.joblib --output results.json
```

### 2.4 `chimera run`

Purpose:

- execute the full Chimera engine pipeline from config

Typical usage:

```bash
chimera run --config chimera.yaml --input auth.csv --output ./chimera_output
```

This is the best command when you want the complete research stack rather than only detector scoring.

### 2.5 `chimera bench`

Purpose:

- run a controlled synthetic benchmark on a local dataset

Typical usage:

```bash
chimera bench --config chimera.yaml --input auth.csv --injection-type session_hijack
```

### 2.6 `chimera bench-lanl`

Purpose:

- run a benchmark against a streamed LANL-style auth slice

Typical usage:

```bash
chimera bench-lanl --config chimera.yaml --input auth.txt --limit 50000
```

### 2.7 `chimera doctor`

Purpose:

- validate runtime health for portable embedding and future wrapper use

Typical usage:

```bash
chimera doctor
chimera doctor --json
```

### 2.8 `chimera agent-review`

Purpose:

- generate a deterministic offline analyst summary from a Chimera artifact or output directory

Typical usage:

```bash
chimera agent-review --input ./chimera_output
chimera agent-review --input ./chimera_output --output ./chimera_agent_review --json
```

## 3. Supporting Commands

Other commands support surrounding workflows:

- `chimera report`
- `chimera rules`
- `chimera correlate`
- `chimera export`
- `chimera baseline`
- `chimera watch`
- `chimera info`
- `chimera agent-review`

These help inspect, package, or operationalize results without changing the project’s research-first orientation.

## 4. Common Output Types

### 4.1 Model artifacts

Produced during training:

- `.joblib` model artifact
- model metadata JSON
- integrity manifest when enabled

### 4.2 Runtime output directories

Produced during `run`:

- scored events
- report files
- engine summary artifacts

### 4.3 Benchmark artifacts

Produced during `bench` and `bench-lanl`:

- `bench_report.json`
- `bench_report.md`
- suite summaries for multi-run workflows
- `artifact_manifest.json`

## 5. Why Markdown Reports Matter

Chimera emits Markdown benchmark reports because research workflows often need:

- quick review before publishing
- version-to-version comparison
- human-readable summaries
- representative examples for interpretation

JSON alone is not enough for that.

## 6. Identity Research Channels in Output

Depending on the path and config, outputs may include channels such as:

- `identity_sequence_score`
- `identity_relationship_score`
- `identity_fusion_score`
- `identity_campaign_score`
- `identity_password_spray_score`
- `identity_low_and_slow_score`
- `identity_takeover_sequence_score`
- `identity_takeover_score`

Portable runtime envelopes may also include:

- `cases`
- `case_summary`
- `case_metrics`
- `artifacts`

Agent-review envelopes include:

- `review`
- analyst posture
- top cases
- recommendation list

These exist so the identity layer can be studied directly rather than hidden inside a single fused score.

## 7. Explainability Fields

Chimera tries to surface reasons in a compact, practical way.

Examples include:

- identity reasons attached to benchmark examples
- rule matches
- structured report sections highlighting representative findings

The project favors concrete reasons over generic confidence theater.

## 8. Integrity Expectations

Model loading is intentionally strict:

- verified artifacts are preferred
- unsigned model artifacts are refused by default when integrity is enabled

This matters because Chimera is meant to be safe enough for controlled local deployment, not just convenient in a benchmark notebook.

## 9. Recommended Usage Pattern

For most serious work, the recommended progression is:

1. `chimera init`
2. `chimera train`
3. `chimera run`
4. `chimera bench`
5. `chimera bench-lanl`

That sequence gives you a grounded understanding of both operational behavior and research performance.

## 10. CLI Philosophy

The CLI should help Chimera feel like a serious research package:

- clear entry points
- explainable outputs
- reproducible artifacts
- enough visual identity to feel intentional
- a stable machine-facing contract for wrapper consumers

That is why v0.6.0 includes stronger command-line presentation without turning the tool into a noisy or theatrical shell app.

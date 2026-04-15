# Chimera Evaluation Playbook

This guide explains how Chimera’s evaluation story works in v0.5.1 and how to use it for serious identity-behavior research rather than generic anomaly demos.

## 1. Evaluation Philosophy

Chimera should be judged by whether it can support defensible identity-centric research claims.

That means evaluation must answer:

- does the identity layer improve on baseline detectors?
- where does it improve?
- where does it remain weak?
- how stable are thresholds under contamination and attack variation?
- can the system explain representative detections clearly?

## 2. Benchmark Structure

Each benchmark run has four major stages:

1. load a local source dataset
2. inject a deterministic synthetic attack family
3. score both baseline and Chimera paths
4. generate JSON and Markdown reports

The benchmark harness exists so the project can compare:

- detector-only behavior
- detector-plus-identity behavior
- attack-family-specific response

## 3. Supported Attack Families

Current supported synthetic families include:

- `session_hijack`
- `mfa_bypass`
- `low_and_slow`
- `password_spraying`
- `coordinated_campaign`
- `identity_drift`
- `temporal_jitter`

These families are intentionally identity-centered rather than generic volume-only stressors.

## 4. Core Metrics

The benchmark outputs are designed to emphasize research usefulness:

- detection lift
- false-positive rate behavior
- threshold stability
- disagreement entropy
- contamination-shift robustness
- representative explainability examples

Not every family will show the same lift profile. That is expected and should be reported honestly.

## 5. Recommended Research Questions

Useful comparisons include:

- baseline detectors vs baseline plus identity features
- campaign-focused slices vs generic anomaly slices
- sequence-heavy attacks vs relationship-heavy attacks
- difficult jittered attacks vs naive burst attacks
- sparse-user cases vs dense-user baselines

## 6. CLI Workflows

### 6.1 Single benchmark

```bash
chimera bench --config chimera.yaml --input auth.csv --injection-type session_hijack
```

### 6.2 Campaign benchmark

```bash
chimera bench --config chimera.yaml --input auth.csv --injection-type password_spraying
chimera bench --config chimera.yaml --input auth.csv --injection-type low_and_slow
```

### 6.3 LANL-style suite

```bash
python scripts/run_lanl_benchmark.py --config chimera.yaml --input auth.txt --preset publishable_identity
```

## 7. Report Artifacts

Typical outputs include:

- `bench_report.json`
- `bench_report.md`
- `lanl_suite_summary.json`
- `lanl_suite_report.md`

The JSON is for programmatic inspection. The Markdown is for review, release prep, and research writing.

## 8. Report Slice Interpretation

The evaluation config now supports richer report slices such as:

- `session_focus`
- `geo_focus`
- `campaign_focus`
- `spray_focus`
- `low_and_slow_focus`

These slices matter because Chimera’s identity layer is not trying to be equally strong on every anomaly family. It is trying to be measurably better on identity-centered families.

## 9. Good Evaluation Discipline

Recommended habits:

- keep seeds fixed while making architectural comparisons
- compare against the same base dataset distribution
- preserve representative examples in reports
- avoid overstating lift from one favorable attack family
- document where baseline detectors still outperform the identity stack

## 10. What “Good” Looks Like

A strong Chimera evaluation story should include:

- at least one detector-only baseline
- at least one identity-heavy family where Chimera clearly helps
- threshold behavior, not only top-line recall
- explainability examples
- a written interpretation of where the identity layer helps and where it does not

## 11. Current Known Weak Spots

The evaluation story is materially stronger than before, but still not complete.

Current pressure points:

- stronger real-world validation
- better difficult spray distributions
- more longitudinal drift cases
- sparse-identity stress testing
- stronger publication-grade tables across multiple datasets

## 12. Suggested Release-Grade Benchmark Set

For a release-quality local evaluation pass, run:

1. `session_hijack`
2. `mfa_bypass`
3. `password_spraying`
4. `low_and_slow`
5. one LANL-style suite

That set provides a balanced picture of sequence, relationship, and campaign behavior without pretending the project has universal coverage.

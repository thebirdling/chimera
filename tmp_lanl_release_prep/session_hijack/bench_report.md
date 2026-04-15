# Chimera Research Benchmark Report

*Generated: 2026-04-15 10:21:40 UTC*

## Study Setup

- Dataset: `lanl_auth`
- Attack family: `session_hijack`
- Injection magnitude: `3.0`
- Seed: `42`
- Original events: `110`
- Injected events: `62`

## Headline Results

| Metric | Baseline | Chimera | Lift |
|---|---:|---:|---:|
| Detection rate @ FPR=0.01 | 0.000 | 0.000 | 0.000 |
| Detection rate @ FPR=0.05 | 0.000 | 0.000 | 0.000 |
| Detection rate @ FPR=0.1 | 0.000 | 0.000 | 0.000 |
| Detection rate @ FPR=0.2 | 0.000 | 0.000 | 0.000 |

## Robustness Diagnostics

| Metric | Baseline | Chimera |
|---|---:|---:|
| Threshold drift mean | 0.0000 | 0.0000 |
| Disagreement entropy mean | 0.3821 | 2.0027 |
| Score variance mean | 66.3132 | 0.1644 |
| False positive rate observed | 1.0000 | 0.0000 |

## Slice Analysis

| Slice | Events | Baseline detected | Chimera detected | Chimera mean score |
|---|---:|---:|---:|---:|
| takeover_only | 61 | 1.000 | 1.000 | 1.000 |
| coordination_heavy | 61 | 1.000 | 1.000 | 0.996 |
| infra_reuse_heavy | 0 | 0.000 | 0.000 | 0.000 |
| mfa_bypass_focus | 0 | 0.000 | 0.000 | 0.000 |
| session_concurrency_focus | 61 | 1.000 | 1.000 | 1.000 |
| geo_velocity_focus | 7 | 1.000 | 1.000 | 1.000 |
| spray_focus | 0 | 0.000 | 0.000 | 0.000 |
| low_and_slow_focus | 0 | 0.000 | 0.000 | 0.000 |
| campaign_focus | 61 | 1.000 | 1.000 | 0.996 |

## Representative Findings

### Event 52 - U15

- Timestamp: `2010-01-01T02:39:08`
- Event type: `session_refresh`
- Session id: `hijack-U15`
- Identity fusion score: `0.557`
- Takeover score: `1.000`
- Campaign score: `0.040`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for U15 within the burst window.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.
- Reason: The same session was active under divergent network or browser context.

### Event 55 - U15

- Timestamp: `2010-01-01T02:39:12`
- Event type: `session_refresh`
- Session id: `hijack-U15`
- Identity fusion score: `0.557`
- Takeover score: `1.000`
- Campaign score: `0.040`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for U15 within the burst window.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.
- Reason: The same session was active under divergent network or browser context.

### Event 51 - U15

- Timestamp: `2010-01-01T02:39:05`
- Event type: `session_refresh`
- Session id: `hijack-U15`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for U15 within the burst window.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.
- Reason: An existing session shifted across multiple identity-context dimensions.

### Event 53 - U15

- Timestamp: `2010-01-01T02:39:08`
- Event type: `session_refresh`
- Session id: `hijack-U15`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for U15 within the burst window.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.
- Reason: An existing session shifted across multiple identity-context dimensions.

### Event 56 - U15

- Timestamp: `2010-01-01T02:39:14`
- Event type: `session_refresh`
- Session id: `hijack-U15`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for U15 within the burst window.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.
- Reason: An existing session shifted across multiple identity-context dimensions.

### Event 106 - U15

- Timestamp: `2010-01-01T02:42:00`
- Event type: `privileged_action`
- Session id: `hijack-U15`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `1.000`
- Reason: Inter-event timing deviates sharply from U15's baseline rhythm.
- Reason: An existing session shifted across multiple identity-context dimensions.
- Reason: The same session was active under divergent network or browser context.
- Reason: Session fingerprint drift suggests token reuse under a changed client context.

### Event 107 - U15

- Timestamp: `2010-01-01T02:43:00`
- Event type: `privileged_action`
- Session id: `hijack-U15`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `1.000`
- Reason: Rapid sequence cadence for U15 within the burst window.
- Reason: Inter-event timing deviates sharply from U15's baseline rhythm.
- Reason: An existing session shifted across multiple identity-context dimensions.
- Reason: The same session was active under divergent network or browser context.

### Event 108 - U15

- Timestamp: `2010-01-01T02:44:00`
- Event type: `privileged_action`
- Session id: `hijack-U15`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `1.000`
- Reason: Rapid sequence cadence for U15 within the burst window.
- Reason: Inter-event timing deviates sharply from U15's baseline rhythm.
- Reason: An existing session shifted across multiple identity-context dimensions.
- Reason: The same session was active under divergent network or browser context.

## Interpretation

Chimera performs best when detector baselines are augmented with structured identity reasoning
for ordered takeover behavior, coordinated cross-account campaigns, and explainable session drift.

# Chimera Research Benchmark Report

*Generated: 2026-04-15 10:20:43 UTC*

## Study Setup

- Dataset: `generic_auth`
- Attack family: `session_hijack`
- Injection magnitude: `3.0`
- Seed: `42`
- Original events: `422`
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
| Disagreement entropy mean | 1.6721 | 1.9906 |
| Score variance mean | 5791.2600 | 0.1636 |
| False positive rate observed | 0.6667 | 0.3583 |

## Slice Analysis

| Slice | Events | Baseline detected | Chimera detected | Chimera mean score |
|---|---:|---:|---:|---:|
| takeover_only | 61 | 1.000 | 1.000 | 1.000 |
| coordination_heavy | 61 | 1.000 | 1.000 | 0.997 |
| infra_reuse_heavy | 0 | 0.000 | 0.000 | 0.000 |
| mfa_bypass_focus | 0 | 0.000 | 0.000 | 0.000 |
| session_concurrency_focus | 61 | 1.000 | 1.000 | 1.000 |
| geo_velocity_focus | 61 | 1.000 | 1.000 | 1.000 |
| spray_focus | 0 | 0.000 | 0.000 | 0.000 |
| low_and_slow_focus | 0 | 0.000 | 0.000 | 0.000 |
| campaign_focus | 61 | 1.000 | 1.000 | 0.997 |

## Representative Findings

### Event 195 - user_11

- Timestamp: `2026-01-08T09:41:08`
- Event type: `session_refresh`
- Session id: `hijack-user_11`
- Identity fusion score: `0.595`
- Takeover score: `1.000`
- Campaign score: `0.100`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for user_11 within the burst window.
- Reason: Inter-event timing deviates sharply from user_11's baseline rhythm.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.

### Event 198 - user_11

- Timestamp: `2026-01-08T09:41:12`
- Event type: `session_refresh`
- Session id: `hijack-user_11`
- Identity fusion score: `0.595`
- Takeover score: `1.000`
- Campaign score: `0.100`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for user_11 within the burst window.
- Reason: Inter-event timing deviates sharply from user_11's baseline rhythm.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.

### Event 194 - user_11

- Timestamp: `2026-01-08T09:41:05`
- Event type: `session_refresh`
- Session id: `hijack-user_11`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for user_11 within the burst window.
- Reason: Inter-event timing deviates sharply from user_11's baseline rhythm.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.

### Event 196 - user_11

- Timestamp: `2026-01-08T09:41:08`
- Event type: `session_refresh`
- Session id: `hijack-user_11`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for user_11 within the burst window.
- Reason: Inter-event timing deviates sharply from user_11's baseline rhythm.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.

### Event 199 - user_11

- Timestamp: `2026-01-08T09:41:14`
- Event type: `session_refresh`
- Session id: `hijack-user_11`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `0.500`
- Reason: Rapid sequence cadence for user_11 within the burst window.
- Reason: Inter-event timing deviates sharply from user_11's baseline rhythm.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.

### Event 249 - user_11

- Timestamp: `2026-01-08T09:44:00`
- Event type: `privileged_action`
- Session id: `hijack-user_11`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `1.000`
- Reason: Inter-event timing deviates sharply from user_11's baseline rhythm.
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: An existing session shifted across multiple identity-context dimensions.
- Reason: The same session was active under divergent network or browser context.

### Event 250 - user_11

- Timestamp: `2026-01-08T09:45:00`
- Event type: `privileged_action`
- Session id: `hijack-user_11`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `1.000`
- Reason: Rapid sequence cadence for user_11 within the burst window.
- Reason: Inter-event timing deviates sharply from user_11's baseline rhythm.
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: An existing session shifted across multiple identity-context dimensions.

### Event 251 - user_11

- Timestamp: `2026-01-08T09:46:00`
- Event type: `privileged_action`
- Session id: `hijack-user_11`
- Identity fusion score: `0.505`
- Takeover score: `1.000`
- Campaign score: `0.010`
- Takeover sequence score: `1.000`
- Reason: Rapid sequence cadence for user_11 within the burst window.
- Reason: Inter-event timing deviates sharply from user_11's baseline rhythm.
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: An existing session shifted across multiple identity-context dimensions.

## Interpretation

Chimera performs best when detector baselines are augmented with structured identity reasoning
for ordered takeover behavior, coordinated cross-account campaigns, and explainable session drift.

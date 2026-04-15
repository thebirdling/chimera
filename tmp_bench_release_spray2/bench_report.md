# Chimera Research Benchmark Report

*Generated: 2026-04-15 10:23:13 UTC*

## Study Setup

- Dataset: `generic_auth`
- Attack family: `password_spraying`
- Injection magnitude: `3.0`
- Seed: `42`
- Original events: `374`
- Injected events: `14`

## Headline Results

| Metric | Baseline | Chimera | Lift |
|---|---:|---:|---:|
| Detection rate @ FPR=0.01 | 0.000 | 0.000 | -0.071 |
| Detection rate @ FPR=0.05 | 0.000 | 0.000 | -0.071 |
| Detection rate @ FPR=0.1 | 0.000 | 0.000 | -0.071 |
| Detection rate @ FPR=0.2 | 0.000 | 0.000 | -0.071 |

## Robustness Diagnostics

| Metric | Baseline | Chimera |
|---|---:|---:|
| Threshold drift mean | 0.0000 | 0.0000 |
| Disagreement entropy mean | 1.3054 | 2.3792 |
| Score variance mean | 37.3063 | 0.1932 |
| False positive rate observed | 0.8972 | 0.8667 |

## Slice Analysis

| Slice | Events | Baseline detected | Chimera detected | Chimera mean score |
|---|---:|---:|---:|---:|
| takeover_only | 1 | 1.000 | 1.000 | 1.000 |
| coordination_heavy | 13 | 1.000 | 0.923 | 0.690 |
| infra_reuse_heavy | 13 | 1.000 | 0.923 | 0.690 |
| mfa_bypass_focus | 0 | 0.000 | 0.000 | 0.000 |
| session_concurrency_focus | 1 | 1.000 | 1.000 | 1.000 |
| geo_velocity_focus | 14 | 1.000 | 0.929 | 0.712 |
| spray_focus | 12 | 1.000 | 1.000 | 0.718 |
| low_and_slow_focus | 11 | 1.000 | 1.000 | 0.726 |
| campaign_focus | 13 | 1.000 | 0.923 | 0.690 |

## Representative Findings

### Event 1 - user_01

- Timestamp: `2026-01-07T02:00:00`
- Event type: `failed_login`
- Session id: `s-user_01-280`
- Identity fusion score: `0.500`
- Takeover score: `0.875`
- Campaign score: `0.000`
- Takeover sequence score: `0.000`
- Reason: Rapid sequence cadence for user_01 within the burst window.
- Reason: Country transition occurred inside the suspicious relation window.
- Reason: The implied travel speed between session locations is operationally implausible.
- Reason: The session touched a country that is elevated in the local risk model.

### Event 11 - user_11

- Timestamp: `2026-01-07T02:07:30`
- Event type: `failed_login`
- Session id: `s-user_01-280`
- Identity fusion score: `0.600`
- Takeover score: `0.300`
- Campaign score: `1.000`
- Takeover sequence score: `0.000`
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: Network identity shifted outside user_11's prior baseline.
- Reason: Device fingerprint is new for user_11.
- Reason: Failure pattern resembles password spraying across multiple peer identities from one source.

### Event 12 - user_12

- Timestamp: `2026-01-07T02:08:15`
- Event type: `failed_login`
- Session id: `s-user_01-280`
- Identity fusion score: `0.600`
- Takeover score: `0.300`
- Campaign score: `1.000`
- Takeover sequence score: `0.000`
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: Network identity shifted outside user_12's prior baseline.
- Reason: Device fingerprint is new for user_12.
- Reason: Failure pattern resembles password spraying across multiple peer identities from one source.

### Event 13 - user_13

- Timestamp: `2026-01-07T02:09:00`
- Event type: `failed_login`
- Session id: `s-user_01-280`
- Identity fusion score: `0.600`
- Takeover score: `0.300`
- Campaign score: `1.000`
- Takeover sequence score: `0.000`
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: Network identity shifted outside user_13's prior baseline.
- Reason: Device fingerprint is new for user_13.
- Reason: Failure pattern resembles password spraying across multiple peer identities from one source.

### Event 14 - user_14

- Timestamp: `2026-01-07T02:09:45`
- Event type: `failed_login`
- Session id: `s-user_01-280`
- Identity fusion score: `0.600`
- Takeover score: `0.300`
- Campaign score: `1.000`
- Takeover sequence score: `0.000`
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: Network identity shifted outside user_14's prior baseline.
- Reason: Device fingerprint is new for user_14.
- Reason: Failure pattern resembles password spraying across multiple peer identities from one source.

### Event 10 - user_10

- Timestamp: `2026-01-07T02:06:45`
- Event type: `failed_login`
- Session id: `s-user_01-280`
- Identity fusion score: `0.600`
- Takeover score: `0.298`
- Campaign score: `0.980`
- Takeover sequence score: `0.000`
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: Network identity shifted outside user_10's prior baseline.
- Reason: Device fingerprint is new for user_10.
- Reason: Failure pattern resembles password spraying across multiple peer identities from one source.

### Event 9 - user_09

- Timestamp: `2026-01-07T02:06:00`
- Event type: `failed_login`
- Session id: `s-user_01-280`
- Identity fusion score: `0.593`
- Takeover score: `0.296`
- Campaign score: `0.960`
- Takeover sequence score: `0.000`
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: Network identity shifted outside user_09's prior baseline.
- Reason: Device fingerprint is new for user_09.
- Reason: Failure pattern resembles password spraying across multiple peer identities from one source.

### Event 8 - user_08

- Timestamp: `2026-01-07T02:05:15`
- Event type: `failed_login`
- Session id: `s-user_01-280`
- Identity fusion score: `0.540`
- Takeover score: `0.294`
- Campaign score: `0.940`
- Takeover sequence score: `0.000`
- Reason: The session touched a country that is elevated in the local risk model.
- Reason: Network identity shifted outside user_08's prior baseline.
- Reason: Device fingerprint is new for user_08.
- Reason: Failure pattern resembles password spraying across multiple peer identities from one source.

## Interpretation

Chimera performs best when detector baselines are augmented with structured identity reasoning
for ordered takeover behavior, coordinated cross-account campaigns, and explainable session drift.

# Chimera Research Brief

**Version**: 0.5.1  
**Date**: April 2026

## 1. Abstract

Chimera is an offline-first research framework for authentication and identity-behavior anomaly analysis. The project investigates how unsupervised detectors, deterministic rules, robust ensemble scoring, and structured identity reasoning can be combined in constrained environments where network enrichment, centralized telemetry, and dense labels are unavailable or undesirable.

Chimera v0.5.1 advances the project from robust anomaly scoring toward **structured identity-behavior reasoning**. The current system emphasizes deterministic sequence and relationship signals, coordinated identity attack heuristics, explainable outputs, and reproducible benchmark workflows.

## 2. Problem Statement

Most contemporary security analytics stacks assume:

- cloud enrichment is available
- internet egress is acceptable
- large telemetry lakes are normal
- labels or prior detections can bootstrap the system

Those assumptions break down in:

- air-gapped environments
- forensic research settings
- sensitive local investigations
- constrained infrastructure environments
- early-stage prototyping where reproducibility matters more than platform breadth

Chimera asks a narrower but sharper question:

> how far can we push identity and authentication anomaly research using local, reproducible, adversarially robust methods?

## 3. Design Principles

### 3.1 Offline-First

Core workflows must run locally and remain useful without external graph services, live threat feeds, or cloud feature stores.

### 3.2 Identity-Focused

The primary subject is not generic telemetry. It is authentication and identity behavior:

- session continuity
- login cadence
- device drift
- geography shifts
- cross-account overlap
- coordinated account abuse

### 3.3 Adversarially Robust

Integrity, persistence safety, contamination handling, and threshold stability are part of the system design rather than afterthoughts.

### 3.4 Research-Grade and Reproducible

Deterministic seeds, controlled synthetic injections, and comparable reporting matter because Chimera is intended to support defensible claims rather than vague product language.

## 4. Current Technical Stack

Chimera’s research architecture now consists of five interacting layers:

1. local ingestion into a canonical authentication-event schema
2. behavioral and identity feature engineering
3. unsupervised baseline detectors
4. robust ensemble scoring and thresholding
5. sequence, relationship, and campaign-aware identity reasoning

This means Chimera no longer treats every authentication event as an isolated point. It increasingly treats events as parts of:

- sessions
- user-level behavioral sequences
- shared-entity relationship structures
- local campaign patterns

## 5. Behavioral and Identity Features

### 5.1 Baseline Behavioral Features

Chimera already includes:

- temporal rhythm features
- event velocity
- entropy-based indicators for IP and geography diversity
- peer-group deviation features
- impossible-travel style geography indicators
- session and device continuity signals

These remain foundational because the identity layer is additive, not a replacement.

### 5.2 Structured Identity Features

The current phase adds deterministic identity reasoning primitives:

- session cadence and short-range ordering
- burst and replay-style session behavior
- fingerprint drift within session context
- shared IP and shared device overlap
- ASN concentration
- synchronized cross-user activity
- fan-out and multi-account infrastructure reuse
- password-spraying indicators
- low-and-slow coordinated abuse indicators
- ordered takeover progression from initial session establishment through reuse and privileged action

The design choice is deliberate: Chimera prefers deterministic, inspectable features over deep neural sequence models at this stage.

## 6. Modeling Strategy

### 6.1 Baseline Detector Layer

Chimera uses unsupervised baselines such as:

- Isolation Forest
- Local Outlier Factor

These provide pointwise anomaly signals with complementary strengths.

### 6.2 Robust Ensemble Layer

Because raw detector outputs are unstable in constrained settings, Chimera uses:

- score normalization
- ensemble voting
- dynamic thresholding
- disagreement and instability diagnostics

This layer is essential to making baseline detector outputs comparable and reproducible.

### 6.3 Identity Reasoning Layer

The identity layer consumes feature outputs and emits:

- `identity_sequence_score`
- `identity_relationship_score`
- `identity_campaign_score`
- `identity_takeover_sequence_score`
- `identity_takeover_score`

It also emits human-readable reasons so findings are reviewable by analysts and usable in research writeups.

## 7. Why Deterministic Sequence and Graph Reasoning First

The project deliberately avoids jumping straight to deep learning for three reasons:

### 7.1 Defensibility

Deterministic signals are easier to reason about, ablate, compare, and publish.

### 7.2 Infrastructure Fit

Local feature-driven sequence and graph statistics fit the project’s constrained-infrastructure thesis better than heavy training loops or external graph systems.

### 7.3 Interpretability

Human-readable reasons matter for both analysts and research communication. Deterministic features support this naturally.

## 8. Evaluation Methodology

Chimera’s evaluation harness is now identity-centric rather than only generic anomaly-centric.

Supported synthetic attack families include:

- session hijack
- MFA bypass style drift
- password spraying
- low-and-slow credential abuse
- coordinated multi-account campaigns
- temporal jitter

Reporting emphasizes:

- detection lift
- false-positive behavior
- threshold stability
- contamination-shift robustness
- explainability examples

LANL-style workflows and Markdown benchmark artifacts are included so experiments can be rerun and reviewed without needing custom post-processing.

## 9. Security and Operational Discipline

Chimera v0.5.1 includes several important safety boundaries:

- model loading requires integrity verification by default
- runtime paths preserve local operation assumptions
- native acceleration is optional and backed by Python fallbacks
- the research platform does not depend on external graph infrastructure

This does not make Chimera a hardened public SaaS platform. It means the project is serious about the trust assumptions within its intended offline research environment.

## 10. Current Limitations

Chimera remains intentionally constrained in several ways:

- it is still focused on authentication and identity behavior rather than broad endpoint and network telemetry
- broad vendor-specific log normalization is incomplete
- sparse-user and cold-start behavior still need better calibration
- some attack families remain stronger in concept than in benchmark lift across every synthetic distribution
- topology remains exploratory rather than central

These are active research boundaries, not hidden weaknesses.

## 11. Research Positioning

The most accurate way to describe Chimera today is:

- offline-first
- identity-focused
- adversarially robust
- research-grade
- reproducible

The least accurate way to describe Chimera today is:

- a universal cyber defense product
- a finished internet-facing platform
- a broad telemetry replacement for cloud SIEM ecosystems

## 12. Near-Term Research Agenda

The strongest next steps are:

- more rigorous real-dataset validation
- stronger ablations between baseline and identity-aware layers
- better campaign benchmark difficulty calibration
- richer sparse-identity handling
- publication-quality examples and evaluation tables

## 13. Conclusion

Chimera’s differentiator is not that it performs anomaly detection offline. Many systems can do that in a limited sense.

Its differentiator is that it treats offline, constrained, identity-centric anomaly research as a first-class engineering and scientific problem, then builds:

- robust scoring foundations
- deterministic identity reasoning
- local coordination analysis
- reproducible evaluation

around that premise.

That is the real shape of Chimera in v0.5.1.

# Chimera Research Brief: Identity-Centric Behavioral Research Under Constrained Infrastructure

**Version**: 0.5.0  
**Date**: April 2026

## 1. Introduction

The proliferation of cloud-native SIEMs (Security Information and Event Management) has created a dependency on external APIs and centralized data lakes for threat detection. While effective for enterprise environments, these solutions are often unsuitable for high-security, air-gapped, or forensic research contexts where data sovereignty and offline operation are paramount.

This brief outlines the design and implementation of **Chimera**, an offline-first research framework for identity and authentication anomaly analysis. Chimera v0.5.0 investigates how unsupervised detectors, deterministic rules, sequence-aware identity reasoning, and campaign heuristics can be combined under infrastructure and reproducibility constraints.

## 2. Infrastructure Constraints

Chimera was designed under strict constraints to model specific high-security scenarios:
- **Zero Network Egress**: No API calls for threat intelligence or model updates.
- **Local Compute Only**: All processing must run on a standard researcher workstation.
- **No Labeled Data**: Detection must rely on unsupervised learning and heuristic rules, as attack labels are rarely available in real-time.

These constraints necessitated a feature-rich, ensemble-based approach to compensate for the lack of global threat intelligence feeds.

## 3. Behavioral Feature Engineering

We implemented a robust feature extraction pipeline transforming raw authentication logs into behavioral vectors spanning temporal rhythm, geography, device reuse, session continuity, coordination, and campaign structure. Key innovations in v0.5.0 include:

### 3.1 Entropy-Based Features
To capture the randomness of a user's access patterns, we compute the Shannon entropy of their IP, device, and country distributions over a sliding window.
$$ H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i) $$
Sudden spikes in entropy often correlate with credential compromise or bot activity.

### 3.2 Peer-Group Deviation
Unlike standard UEBA which compares a user to their own history, Chimera introduces a global "peer group" baseline. We measure the deviation of a user's velocity (events/hour) and timing against the global cohort mean.
$$ Z_{peer} = \frac{x_{user} - \mu_{global}}{\sigma_{global}} $$
This helps detect compromised accounts behaving "normally" for themselves but anomalously compared to the organization.

### 3.3 Structured Identity Reasoning

The current research phase adds deterministic identity primitives:

- session cadence and fingerprint drift
- shared IP, device, and ASN relationship features
- password-spraying and low-and-slow campaign heuristics
- ordered takeover progression from login to token reuse to privileged action

These features are additive to the baseline detectors and remain fully offline and reproducible.

## 4. Ensemble Modeling Strategy

Single-model anomaly detection often suffers from high false positives (Isolation Forest) or insensitivity to local density clusters (LOF). Chimera implements a heterogeneous ensemble:

1.  **Isolation Forest**: Efficient for global outliers.
2.  **Local Outlier Factor (LOF)**: Effective for local density anomalies.
3.  **Ensemble Voting**:
    - **Normalization**: Raw scores from constituent models are robustly scaled to $[0, 1]$ using MinMax scaling fitted on the training distribution.
    - **Dynamic Thresholding**: The decision boundary is not fixed but determined dynamically by the `contamination` percentile of the ensemble score distribution.

This voting mechanism aims to reduce noise while maintaining high recall for distinct anomaly types.

## 5. Offline Threat Intelligence

To enrich detections without network access, Chimera introduces a local provider interface (`chimera.threat_intel`). This module loads static indicators (IP/ASN blocklists) from flat files into memory sets. These are then joined with authentication events during the feature engineering phase, treating "known bad" status as a strong feature signal rather than a simple filter.

## 6. Experimental Observations

Initial verification on synthetic datasets and LANL-style benchmark slices demonstrated:
- **Robustness**: the ensemble-plus-identity stack detects session hijack, MFA bypass, password spraying, and coordinated campaign patterns more reliably than detector-only baselines.
- **Determinism**: Fixed random seeding ensured identical anomaly scores across repeated runs, a critical requirement for forensic reproducibility.
- **Explainability**: event-level identity reasons and benchmark markdown reporting provide clear research examples for analyst review and publication workflows.

## 7. Limitations

- **Compute Scaling**: LOF is $O(n^2)$ complexity, limiting scalability on large datasets without subsampling.
- **Static Rules**: the rule engine still requires manual configuration updates.
- **Cold Start**: New users with insufficient history may generate false positives until baselines stabilize (approx. 50 events).

## 8. Future Work

- **Sequence Modeling**: extend the current deterministic sequence layer before considering heavier learned models.
- **Active Learning**: Introducing a feedback loop for analysts to label anomalies, enabling semi-supervised refinement.
- **Graph correlation**: deepen the current local structural graph signals without requiring external graph infrastructure.

---
*For technical details and contribution guidelines, refer to the [GitHub Repository](https://github.com/thebirdling/chimera).*

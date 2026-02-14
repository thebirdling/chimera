![Open Graph, Homepage (1)](https://cdn.thebirdling.com/github/images/chimera-git-cover.png)

# Chimera: Modular Behavioral Authentication Research Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status: Research Prototype](https://img.shields.io/badge/Status-Research%20Prototype-orange.svg)](CONTRIBUTING.md)

> **⚠️ RESEARCH ARTIFACT DISCLAIMER**  
> Chimera is designed as an extensible framework for **behavioral security research** and **offline forensic analysis**. It is **not** a production-grade SIEM or commercial endpoint protection platform. Use for research, education, and controlled analysis.

---
[![Contribute](https://cdn.thebirdling.com/github/images/small-button-github.svg)](https://github.com/thebirdling/chimera/fork)
---

## 📖 Abstract

Chimera is an offline-first, Python-based framework for detecting anomalies in authentication logs. It implements a hybrid detection strategy combining **unsupervised machine learning** (Isolation Forest, LOF) with **deterministic threat signatures**. Its primary goal is to provide researchers with a reproducible, modular environment to experiment with behavioral feature engineering and ensemble modeling strategies without the opacity of commercial "AI-driven" security tools.

## 🎯 Research Goals

1.  **Transparency**: Decouple detection logic from proprietary cloud platforms.
2.  **Modularity**: Allow detectors to be swapped, combined, and compared.
3.  **Reproducibility**: Ensure deterministic outputs via fixed random seeding.
4.  **Offline Forensics**: Enable analysis of sensitive logs in air-gapped environments.

---

## 🏗️ Architecture Overview

Chimera follows a pipeline architecture designed for extensibility:

```ascii
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Log Source  │───▶│ Data Loader  │───▶│ Feature Eng. │
│ (CSV/JSON/L) │    │ (Stream/Mem) │    │ (Vectorization)│
└──────────────┘    └──────────────┘    └──────┬───────┘
                                               │
                                       ┌───────▼───────┐
                                       │   Ensemble    │
                                       │   Detector    │
                                       │ ┌───┐ ┌───┐   │
                                       │ │IF │ │LOF│...│
                                       │ └───┘ └───┘   │
                                       └───────┬───────┘
                                               │
┌──────────────┐    ┌──────────────┐    ┌──────▼───────┐
│  SIEM Export │◀───│  Correlator  │◀───│    Scorer    │
│ (CEF/STIX 2) │    │ (Cross-User) │    │ (Norm/Thresh)│
└──────────────┘    └──────────────┘    └──────────────┘
```

The system is composed of decoupled modules:
- **Registry**: manages detector lifecycle.
- **Feature Engineer**: transforms raw logs into 30+ behavioral vectors (entropy, velocity, peer-deviation).
- **Rule Engine**: applying traditional signatures (brute-force, impossible travel).
- **Ensemble**: combining model scores via MinMax normalization and rank-based voting.

---

## 🔬 Methodology

### Ensemble Modeling
Chimera employs an ensemble approach to mitigate the weaknesses of individual algorithms.
- **Strategy**: Voting (Mean/Median/Max) of normalized anomaly scores.
- **Normalization**: Raw scores from heterogeneous models (e.g., probability vs. distance) are projected to a [0, 1] interval using MinMax scaling fitted on training data.
- **Dynamic Thresholding**: Decision boundaries are determined dynamically based on the contamination percentile of the *ensemble* score distribution, rather than fixed constants.

### Threat Intelligence Enrichment (Offline)
To support air-gapped research, threat intelligence checks are performed against local blocklists rather than live APIs. The `FeatureEngineer` module integrates with `chimera.threat_intel` to flag known-bad IPs and ASNs as explicit features for the ML models.

---

## 🚀 Quick Start (Reproducibility)

To reproduce a detection run:

1.  **Install**:
    ```bash
    pip install -e .
    ```

2.  **Generate Deterministic Data**:
    ```bash
    # Seed ensures identical dataset generation
    python generate_sample_data.py --users 20 --scenario mixed --seed 42 -o dataset.csv
    ```

3.  **Train Ensemble Model**:
    ```bash
    # Training an ensemble of Isolation Forest + LOF
    chimera train dataset.csv -o model.joblib --detector ensemble --contamination 0.05
    ```

4.  **Run Detection**:
    ```bash
    chimera detect dataset.csv model.joblib -o results.json
    ```

5.  **Audit Determinism**:
    The result hash should be consistent across runs on the same architecture.

---

## 📋 Features & Limitations

| Capability | Status | Limitations |
|------------|--------|-------------|
| **Anomaly Detection** | ✅ Production-Ready | High compute for pure LOF on large datasets |
| **Rule Engine** | ✅ Hardened | Static rules only (conf/rules.yaml) |
| **Correlation** | ✅ Active | Heuristic-based time windows |
| **Threat Intel** | ✅ Local/File-based | No real-time API sync implementation |
| **SIEM Export** | ✅ CEF/Syslog/STIX | STIX 2.1 minimal object set |

---

## 🤝 Contributing

We welcome contributions that align with the research goals (correctness, modularity). Please see [CONTRIBUTING.md](CONTRIBUTING.md) for style guides and type-hint requirements.

## 🛡️ Security

See [SECURITY.md](SECURITY.md) for our offline-first policy and vulnerability reporting.

## 📝 License

MIT License.

## ⚡ Supported By

<a href="https://thebirdling.com">
  <img src="https://assets.basehub.com/38638add/2ae033578930cf8dad65a3e4d01d20b1/basehub-tb-logo-rect-light.svg" alt="The Birdling" width="200" />
</a>

Chimera is maintained and deployed by **The Birdling**'s SPE (Special Projects Engineering) team.

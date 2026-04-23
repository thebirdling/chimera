# Chimera Architecture Overview

This document gives a detailed subsystem-level view of how Chimera is structured in v0.6.0 and how data moves through the system.

## 1. End-to-End Flow

At a high level, Chimera processes local authentication evidence as follows:

1. ingest local authentication records
2. normalize them into a canonical event schema
3. engineer behavioral and identity-oriented features
4. score events with baseline unsupervised detectors
5. normalize and fuse detector outputs through the engine pipeline
6. enrich scoring with identity sequence, relationship, campaign, and takeover signals
7. aggregate related anomalous events into deterministic identity cases
8. emit human-facing reports and machine-facing portable runtime artifacts

## 2. Core Packages

### 2.1 `chimera.data_loader`

Responsibilities:

- parse local auth logs
- normalize fields
- stream LANL-style auth data
- preserve identity attributes required by downstream feature extraction

Key outputs:

- canonical event objects with timestamp, user, source, session, device, and auth context

### 2.2 `chimera.feature_engineering`

Responsibilities:

- transform events into numeric feature vectors
- compute conventional anomaly features
- expose numeric matrices for model training and scoring

Feature groups include:

- time and cadence
- geography and travel indicators
- device continuity
- entropy and diversity
- peer-group deviation

### 2.3 `chimera.identity`

Responsibilities:

- build deterministic identity research features
- model session boundaries and sequence context
- derive local relationship signals
- produce campaign and takeover progression scores
- emit human-readable reason strings

Identity subsignals include:

- session concurrency
- replay burst behavior
- fingerprint drift
- geography velocity
- shared IP and device overlap
- synchronized peer activity
- campaign heuristics
- ordered takeover sequence progression

### 2.4 `chimera.cases`

Responsibilities:

- group related anomalous events into reviewable `IdentityCase` objects
- surface case-level reasoning over the existing event-level identity stack
- support deterministic case summaries for benchmark and runtime artifacts

Initial case families:

- `session_takeover_case`
- `password_spray_case`
- `low_and_slow_campaign_case`
- `coordinated_identity_campaign_case`

### 2.5 `chimera.detectors` and `chimera.model`

Responsibilities:

- provide detector implementations
- manage model configuration and persistence
- expose a stable scoring interface to the CLI and runtime API

Current detector role:

- baseline anomaly estimation

Current non-goal:

- replacing the identity reasoning layer

### 2.6 `chimera.engine`

Responsibilities:

- normalize per-detector scores
- vote or aggregate across detectors
- compute dynamic thresholds
- track threshold stability and disagreement
- enforce integrity expectations for persisted artifacts

This package is the main reason Chimera behaves like a coherent research system rather than a loose detector collection.

### 2.7 `chimera.rules`

Responsibilities:

- provide deterministic, transparent comparison logic
- support explainable built-in checks for identity-centric abuse patterns

Current examples:

- password spraying
- low-and-slow campaigns
- other auth anomaly rule patterns

### 2.8 `chimera.evaluation`

Responsibilities:

- generate deterministic synthetic attack injections
- compare baseline vs Chimera scoring paths
- calculate lift and robustness metrics
- report case-level detection summaries alongside event-level metrics

### 2.9 `chimera.reporting`

Responsibilities:

- serialize result artifacts
- generate benchmark JSON and Markdown
- summarize cases, representative findings, and slice-level metrics

### 2.10 `chimera.api` and `chimera.contracts`

Responsibilities:

- expose the portable runtime layer that future wrappers can call directly
- define stable JSON envelopes for major commands
- define `artifact_manifest.json` for machine discovery of outputs

This is the core of the pre-npm design. Wrappers should consume this layer, not scrape terminal output.

### 2.11 Native acceleration path

Components:

- `chimera/_native/`
- `chimera/_native/rust_graph.py`
- `rust/graph_kernels/`

Responsibilities:

- accelerate expensive local structural kernels
- preserve Python fallback behavior

## 3. Runtime Modes

### 3.1 Training

Training path:

- load events
- engineer numeric features
- fit baseline detector
- persist model artifact
- write integrity information when enabled

### 3.2 Detection

Detection path:

- verify and load model artifact
- engineer features on incoming local data
- score anomalies
- optionally apply rules
- aggregate identity cases
- write stable detection results

### 3.3 Full Engine Run

Full engine path:

- load config
- engineer features
- score with one or more detectors
- inject identity research channels into the raw score map
- run engine normalization and voting
- apply thresholding
- aggregate identity cases
- emit stable run artifacts

### 3.4 Benchmarking

Benchmark path:

- load seed dataset
- inject deterministic attack family
- build ground truth
- score baseline path
- score Chimera path
- compute comparative metrics
- aggregate cases over detected findings
- export JSON and Markdown outputs

### 3.5 Portable Diagnostics

Doctor path:

- validate Python runtime
- validate required dependency imports
- inspect optional native support
- confirm integrity support
- optionally validate config and model artifacts
- run a small runtime health check

## 4. Configuration Model

Chimera’s config system supports multiple layers of control:

- model settings
- feature settings
- scoring settings
- output settings
- runtime contract settings
- engine settings
- identity research settings
- evaluation settings
- integrity settings
- experimental settings

Important v0.6.0 additions:

- `runtime_contract` for stable machine-facing behavior
- case aggregation controls inside `identity_research`

This separation matters because Chimera needs to support controlled ablations instead of one monolithic “on/off” mode.

## 5. Explainability Model

Chimera’s explainability is intentionally pragmatic.

Outputs may include:

- research score channels
- identity reason strings
- case summaries
- per-event examples in benchmark artifacts
- slice-specific examples for publication or analyst review

The system does not attempt a generic XAI layer. It exposes the actual deterministic reasons and case groupings used to create the output.

## 6. Portable Runtime Interpretation

The new portable runtime contract is suitable for:

- Python embedding
- future Node wrapper invocation
- automation pipelines
- local desktop/server orchestration

The portable runtime contract is not intended to:

- replace the human CLI
- hide internal model verification boundaries
- imply a JS rewrite of the core engine

## 7. Deployment Interpretation

The architecture is suitable for:

- local workstation analysis
- controlled research environments
- benchmark and publication workflows
- offline or air-gapped studies
- future wrapper-driven CLI distribution

The architecture is not yet intended as:

- a public internet-facing security service
- a multi-tenant SaaS detection platform
- a cloud-enrichment-first analytics stack

## 8. Current Architectural Strengths

- coherent offline identity-analysis story
- deterministic research layer on top of baseline detectors
- deterministic case-level reasoning
- stable machine-facing runtime contract
- reproducible evaluation
- optional native acceleration without mandatory dependency burden

## 9. Current Architectural Pressure Points

- broader parser coverage
- stronger sparse-user calibration
- more real-world validation datasets
- more comparative analysis of campaign heuristics under difficult distributions
- a real wrapper package in the next version

This document should be read alongside:

- [Research System Map](docs/Research_System_Map.md)
- [Evaluation Playbook](docs/Evaluation_Playbook.md)
- [CLI and Output Guide](docs/CLI_and_Outputs.md)
- [Embedding Chimera](docs/Embedding_Chimera.md)
- [Output Schemas](docs/Output_Schemas.md)

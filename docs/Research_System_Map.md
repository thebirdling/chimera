# Chimera Research System Map

Chimera is an offline-first, identity-focused, adversarially robust research framework for authentication and account-behavior analysis. This document is the durable internal and external map of what Chimera currently is, what is already supported by code, what remains partially implemented, and where the strongest research opportunities still sit.

## 1. Executive Framing

The current thesis for Chimera is:

> robust offline anomaly scoring is useful, but stronger research value emerges when anomaly signals are lifted into structured identity-behavior reasoning.

That shift changes Chimera from a detector bundle into a research platform with three stacked goals:

- produce strong baseline anomaly scores under constrained infrastructure
- model identity behavior using deterministic sequence and relationship features
- evaluate those ideas rigorously with reproducible attack injection and benchmark reporting

## 2. Current Subsystem Roles

### 2.1 Ingestion

Primary files:

- `chimera/data_loader.py`

Current role:

- loads authentication data from local CSV, JSON, and LANL-style auth logs
- normalizes records into a canonical event shape
- preserves enough identity context for downstream session, sequence, geography, and device reasoning

Current status:

- implemented
- actively used by CLI run and benchmark paths

Strengths:

- fully local
- deterministic
- suitable for synthetic and benchmark workflows

Research gaps:

- broader enterprise parser coverage
- more field-preserving normalization for heterogeneous IAM products

### 2.2 Feature Engineering

Primary files:

- `chimera/feature_engineering.py`
- `chimera/identity.py`

Current role:

- transforms raw auth events into numeric and interpretable features
- builds temporal, geography, device, session, peer-group, and identity research signals

Current status:

- implemented
- central to both runtime scoring and benchmark workflows

Strongly supported areas:

- temporal rhythm
- entropy and peer-group deviation
- session continuity and drift
- identity campaign and relationship signals

Research gaps:

- richer long-horizon identity memory
- better handling for sparse users and high-cardinality federated tenants

### 2.3 Detectors

Primary files:

- `chimera/detectors/`
- `chimera/model.py`
- `chimera/registry.py`

Current role:

- provides unsupervised detectors and detector registry support
- preserves baseline scoring for comparative evaluation

Current status:

- implemented

Supported baseline detectors:

- Isolation Forest
- Local Outlier Factor
- registry-wired ensemble patterns

Research framing:

- these detectors are the baseline, not the end state
- Chimera’s novelty is increasingly in how detector outputs are stabilized, contextualized, and fused with identity reasoning

### 2.4 Engine

Primary files:

- `chimera/engine/normalizer.py`
- `chimera/engine/voter.py`
- `chimera/engine/threshold.py`
- `chimera/engine/pipeline.py`
- `chimera/engine/temporal.py`
- `chimera/engine/integrity.py`

Current role:

- robust score normalization
- multi-detector voting
- dynamic thresholding
- temporal drift handling
- artifact integrity and safe persistence

Current status:

- implemented
- core architectural foundation

Evidence-backed claims:

- Chimera is stronger than a naive raw-score stack in terms of reproducibility and threshold control
- integrity verification is part of the actual runtime system, not just a documentation claim

Still needing stronger evidence:

- quantitative advantage across multiple real-world datasets beyond local synthetic and LANL-style slices

### 2.5 Suppression and Triage

Primary files:

- `chimera/suppression.py`
- `chimera/triage.py`

Current role:

- reduce false-positive burden
- support downstream triage and analyst workflow experiments

Current status:

- partially implemented relative to long-term ambition

What is real today:

- the subsystem exists and is wired into the project shape

What remains more exploratory:

- robust, documented, high-confidence triage workflows that are benchmarked as thoroughly as the core identity layer

### 2.6 Fleet and Correlation

Primary files:

- `chimera/fleet_monitor.py`
- `chimera/correlator.py`

Current role:

- look across users rather than only within one user’s history
- support overlap and coordination logic

Current status:

- implemented in a useful but still research-stage form

Research significance:

- this subsystem is where Chimera starts to move from simple UEBA-style self-history toward account-to-account coordination reasoning

### 2.7 Evaluation

Primary files:

- `chimera/evaluation/`
- `scripts/run_lanl_benchmark.py`
- `chimera/reporting.py`

Current role:

- inject deterministic identity attack families
- compare baseline and Chimera scoring paths
- output JSON and Markdown benchmark artifacts

Current status:

- implemented
- materially stronger in the current phase than in earlier releases

Key supported attack families:

- session hijack
- MFA bypass style identity drift
- password spraying
- low-and-slow credential abuse
- coordinated campaign behavior
- temporal jitter

### 2.8 Experimental Topology

Primary files:

- `chimera/experimental/topology.py`

Current role:

- optional comparative topological anomaly sandbox

Current status:

- implemented as optional experimental work
- not the centerpiece of the current thesis

Research conclusion:

- topology remains worth exploring, but the immediate thesis strength lies more clearly in identity-behavior reasoning

### 2.9 Native Acceleration

Primary files:

- `chimera/_native/`
- `chimera/_native/rust_graph.py`
- `rust/graph_kernels/`

Current role:

- accelerate local structural counting and ordered attack progression logic

Current status:

- implemented
- optional by design

Current accelerated kernels:

- shared-entity prior pair counting
- recent peer overlap counting
- ordered takeover sequence progression

Design rule:

- every native path must preserve a Python fallback so default installation remains viable

## 3. Implemented vs Partial vs Artifact-Only

### 3.1 Implemented in Code

- offline ingestion and canonical auth-event handling
- detector baselines
- robust score normalization and thresholding
- integrity verification for model loading
- identity sequence features
- identity relationship features
- campaign heuristics
- ordered takeover progression scoring
- synthetic evaluation harness
- LANL benchmark support
- Markdown benchmark reporting

### 3.2 Partially Implemented

- suppression and triage as a fully benchmarked analyst workflow
- broader enterprise parser ecosystem
- richer long-horizon identity memory
- more comprehensive drift calibration for cold-start and sparse users

### 3.3 Mostly Described in Artifact History or Prior Planning

- broad telemetry expansion beyond authentication
- heavyweight graph infrastructure
- deep learned sequence models
- generalized “all-in-one cybersecurity library” positioning

These are not banned forever, but they are intentionally not the current center of gravity.

## 4. Thesis Evolution

### Phase 1: Offline Behavioral Auth Detection

Chimera began as a local behavioral anomaly framework for authentication logs. The core problem was how to do meaningful auth anomaly work without cloud dependencies or reliable labels.

### Phase 2: Robustness and Hardening

The next major push made the engine itself more defensible:

- score normalization
- detector voting
- threshold stability
- temporal modeling
- integrity and safe persistence

This phase gave Chimera a real systems backbone.

### Phase 3: Identity-Centric Reasoning

The current phase extends beyond per-event scoring into structured reasoning:

- how sessions evolve
- how identities drift
- how accounts relate to one another
- how coordinated campaigns manifest locally
- how ordered attack progressions can be recognized without deep learning or external graph platforms

That is the strongest current articulation of the project.

## 5. Completed Hardening Work

The following hardening work is already real and should be treated as project foundation:

- integrity manifest support
- safe model loading with verification by default
- local persistence discipline
- deterministic seeding
- benchmark reproducibility
- additive identity scoring rather than detector replacement
- optional native acceleration with graceful fallback

## 6. Downgraded or Abandoned Ideas

These ideas are important context, but they are currently downgraded relative to the main thesis:

- broad endpoint and network telemetry expansion
- cloud-dependent “platform” ambitions
- deep sequence models before baseline evaluation is mature
- heavy graph databases for local coordination logic
- product-polish-first work that dilutes the research story

The reason they were downgraded is not lack of ambition. It is that they risk weakening the strongest defensible claim Chimera can make right now.

## 7. Supported Claims vs Claims That Still Need Evidence

### 7.1 Claims Strongly Supported by Code

- Chimera is offline-first
- Chimera is identity-focused
- Chimera is adversarially mindful in its loading and persistence paths
- Chimera supports deterministic identity attack evaluation
- Chimera can emit explainable identity reasons for findings
- Chimera includes additive sequence, relationship, and campaign reasoning

### 7.2 Claims That Need More Evidence Before Strong Public Positioning

- superiority over alternative UEBA approaches in general
- broad enterprise generalization
- robustness across many vendor-specific auth schemas
- topology as a decisive differentiator
- any claim that Chimera is already a universal cyber defense platform

## 8. Open Research Gaps

Highest-value research gaps now:

- stronger real-dataset validation beyond controlled slices
- better handling of sparse identities and cold-start conditions
- ablation studies separating detector value from identity-layer value
- stronger password-spray and low-and-slow comparative lift on harder synthetic distributions
- richer multi-account campaign evaluation tables
- publishable examples with compact narrative explanations

## 9. Strategic Interpretation

The project is most coherent when described as:

- offline-first
- identity-focused
- adversarially robust
- research-grade
- reproducible

It is less coherent when described as:

- a general cyber platform for every security need
- a cloud competitor
- a finished detection product

## 10. Working North Star

The next high-confidence framing for Chimera is:

> from robust anomaly scoring to structured identity-behavior reasoning under constrained infrastructure.

That phrasing matches both the code and the strongest research opportunity in front of the project.

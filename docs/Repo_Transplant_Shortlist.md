# Chimera Repo Transplant Shortlist

This shortlist turns external scavenging into concrete subsystem candidates.
The goal is not to ingest whole products. It is to transplant narrow, testable
ideas into Chimera's offline-first, identity-centric research core without
anchoring the project narrative to outside codebases.

## Priority 1

### `Compact identity-attack heuristic source`
- Why it matters: concise heuristics for credential stuffing and session hijacking.
- Candidate transplant: reusable attack-family logic, especially unique-account burst logic and context-shift takeover checks.
- Target Chimera subsystem: `chimera/evaluation/injector.py`, `chimera/rules/engine.py`, `chimera/identity.py`, `rust/graph_kernels/`.
- Integration rule: transplant logic patterns, not source structure or naming.

### `Rust temporal correlation source A`
- Why it matters: strong reference for temporal and ordered correlation mechanics in Rust.
- Candidate transplant: efficient windowing, ordered sequence logic, compressed event-reference ideas.
- Target Chimera subsystem: future Rust correlation kernels and comparative experimental topology work.
- Integration rule: mine execution patterns, not full external semantics as a dependency.

### `Rust temporal correlation source B`
- Why it matters: useful secondary reference for temporal and ordered correlation execution.
- Candidate transplant: sequence-rule evaluation ideas and alternative rule-shape representations.
- Target Chimera subsystem: rule-engine evolution and experiment-only correlation modules.
- Integration rule: use as a design counterpoint where the Rust APIs diverge.

## Priority 2

### `Geo and session-drift heuristic source`
- Why it matters: focused geo and session-fingerprint logic overlaps with Chimera's identity drift and takeover reasoning.
- Candidate transplant: impossible-travel refinements, IP plus user-agent session fingerprinting, lightweight geovelocity heuristics.
- Target Chimera subsystem: `chimera/feature_engineering.py`, `chimera/identity.py`.
- Integration rule: only transplant heuristics that can stay deterministic and offline.

### `In-memory infrastructure correlation source`
- Why it matters: local infrastructure correlation is close to Chimera's shared-entity and coordinated-campaign thesis.
- Candidate transplant: ASN/provider/country clustering patterns and campaign-style infrastructure grouping.
- Target Chimera subsystem: identity graph features, future offline clustering reports, benchmark slices for coordinated identity abuse.
- Integration rule: prefer local structural statistics over broad enrichment assumptions.

### `Bitmap acceleration source`
- Why it matters: roaring-bitmap acceleration is attractive for high-cardinality entity overlap and scan acceleration.
- Candidate transplant: compact bitmap-backed counters for IP/device/ASN overlap and large-window distinct counts.
- Target Chimera subsystem: future Rust kernels and fleet-scale offline scans.
- Integration rule: only adopt bitmap ideas if they beat the current simpler kernels in profiling.

## Priority 3

### `Correlation spec oracle`
- Why it matters: useful as a validation reference for correlation types and rule semantics.
- Candidate transplant: terminology, validation patterns, and coverage ideas for event-count, value-count, temporal, and temporal-ordered logic.
- Target Chimera subsystem: documentation, future comparative evaluation, optional correlation authoring.
- Integration rule: do not make Chimera depend on an external rule ecosystem to function.

### `Correlation schema validator source`
- Why it matters: helpful reference for correlation schema validation and timespan handling.
- Candidate transplant: config validation patterns and compact rule condition representations.
- Target Chimera subsystem: optional future rule authoring and CLI validation.
- Integration rule: adopt only the schema ideas that improve reproducibility.

## Not Worth Heavy Mining Right Now

- Large dashboard or SOC platform repos with broad product scope.
- General threat-intel platforms that mix UI, reporting, and agent layers without sharp auth-behavior primitives.
- Graph repos that require Neo4j or heavyweight external services.

## Practical Next Step

When a new repo looks promising, map it before touching code:

1. Which single Chimera subsystem could benefit?
2. Is the transplant a heuristic, a kernel pattern, a parser, or an evaluation trick?
3. Can it stay offline, deterministic, and reproducible?
4. What benchmark or test would prove it helped?

# Chimera Output Schemas

This document describes the stable machine-facing output shape introduced in `v0.6.0`.

## 1. Stable Envelope

Major machine-facing commands emit a versioned JSON envelope:

```json
{
  "command": "run",
  "payload": {},
  "status": "ok",
  "schema_version": "1.0",
  "chimera_version": "0.6.0",
  "generated_at": "2026-04-15T18:00:00+00:00"
}
```

Core fields:

- `command`: command identifier such as `run`, `detect`, `bench`, `bench-lanl`, `info`, `doctor`, `agent-review`
- `payload`: command-specific stable payload
- `status`: `ok`, `warn`, or `fail`
- `schema_version`: stable contract version
- `chimera_version`: runtime version
- `generated_at`: UTC timestamp

## 2. Artifact Manifest

Commands that write output directories emit `artifact_manifest.json`:

```json
{
  "schema_version": "1.0",
  "chimera_version": "0.6.0",
  "generated_at": "2026-04-15T18:00:00+00:00",
  "command_type": "bench",
  "generated_files": [
    {
      "name": "bench_report",
      "kind": "json",
      "relative_path": "bench_report.json"
    }
  ]
}
```

Wrappers should use this file for artifact discovery.

## 3. Run Payload

`chimera run --json` payload includes:

- config path
- input path
- threshold
- threshold instability
- event count
- anomaly count
- disagreement entropy mean
- score variance mean
- anomaly indices
- identity research summary
- cases
- case summary
- anomalous events
- artifact paths

## 4. Detect Payload

`chimera detect --json` payload includes:

- metadata summary
- event results
- user summaries
- rule matches
- identity examples
- cases
- case summary
- artifact paths

## 5. Benchmark Payload

`chimera bench --json` and `bench-lanl --json` payloads include:

- dataset label
- injection type
- magnitude
- seed
- baseline metrics
- Chimera metrics
- detection lift at FPR
- benchmark slices
- identity examples
- cases
- case metrics
- artifact paths

## 6. Model Info Payload

`chimera info --json` payload includes:

- model path
- detector metadata
- manifest presence indicator

## 7. Doctor Payload

`chimera doctor --json` payload includes:

- overall status
- list of checks
- runtime version

Typical checks include:

- Python version
- dependency imports
- native acceleration availability
- integrity support
- config readability
- model loadability
- runtime health

## 8. Case Object Shape

Case objects emitted by run, detect, and benchmark flows include:

- `case_id`
- `case_type`
- `severity`
- `confidence_band`
- `score`
- `first_seen`
- `last_seen`
- `involved_users`
- `involved_sessions`
- `involved_ips`
- `involved_devices`
- `involved_asns`
- `representative_event_indices`
- `reasons`

## 9. Agent Review Payload

`chimera agent-review --json` payload includes:

- `review.source_command`
- `review.source_path`
- `review.posture`
- `review.summary`
- `review.case_overview`
- `review.top_cases`
- `review.recommendations`
- `review.hypotheses`
- `review.follow_up_questions`
- optional persisted review artifact paths when `--output` is used

## 10. Compatibility Notes

Stable means:

- the envelope shape should remain safe for wrapper consumption
- schema versioning should gate future breaking changes

Stable does not mean:

- every internal detector or feature name is permanent
- human Markdown report content is a machine contract
- ASCII presentation is machine-parseable

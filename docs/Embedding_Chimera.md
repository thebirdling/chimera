# Embedding Chimera

This guide defines how Chimera should be embedded by automation, desktop tooling, and the future npm wrapper.

## 1. Embedding Philosophy

`v0.6.0` is the pre-npm portable runtime release.

The wrapper boundary is:

- Python remains the source-of-truth execution runtime
- wrappers invoke Chimera commands or Python API entrypoints
- wrappers consume stable JSON envelopes and artifact manifests
- wrappers do not parse branded terminal output

## 2. Supported Embedding Surfaces

### 2.1 Programmatic Python API

Current stable entrypoints:

- `chimera.api.run_pipeline(...)`
- `chimera.api.run_benchmark(...)`
- `chimera.api.inspect_model(...)`
- `chimera.api.doctor(...)`

These return stable envelope objects with:

- `schema_version`
- `command`
- `status`
- `chimera_version`
- `generated_at`
- `payload`

### 2.2 CLI JSON Mode

Major commands support `--json`:

- `chimera run --json`
- `chimera detect --json`
- `chimera bench --json`
- `chimera bench-lanl --json`
- `chimera info --json`
- `chimera doctor --json`

This is the primary contract a non-Python wrapper should target.

## 3. Artifact Discovery

Commands that write to output directories also emit `artifact_manifest.json`.

Wrappers should use the manifest as the source of truth for:

- report file names
- relative paths
- command type
- generated timestamps
- schema version

Wrappers should not hardcode assumptions beyond the stable manifest structure.

## 4. Future npm / npx Boundary

The intended first npm shape is a thin or hybrid enterprise wrapper:

- npm installs or invokes the Python runtime
- the wrapper calls Chimera in JSON mode
- output directories are discovered through artifact manifests
- case summaries and benchmark artifacts are consumed from stable payloads

What the wrapper should not do:

- parse ASCII banners
- parse Markdown reports for data
- reimplement the scoring engine
- bypass integrity-verified model loading

## 5. Recommended Wrapper Flow

For a wrapper-triggered `run` flow:

1. run `chimera doctor --json`
2. run `chimera run ... --json`
3. inspect `payload.artifacts`
4. read `artifact_manifest.json` if the wrapper needs all generated files

For a wrapper-triggered `detect` flow:

1. validate that the model artifact exists
2. run `chimera info --json` if needed
3. run `chimera detect ... --json`
4. read the stable detection payload and case summaries

## 6. Stability Expectations

The stable contract covers:

- envelope shape
- schema version field
- command name
- artifact manifest shape

The stable contract does not promise:

- that every internal feature column will remain unchanged
- that human-facing banner text will remain unchanged
- that Markdown formatting will remain unchanged

## 7. Security Boundary

Embedding does not weaken Chimera’s security model.

Wrappers and embedding layers must respect:

- integrity-verified model loading
- local filesystem trust assumptions
- optional native acceleration behavior

If a wrapper needs looser behavior, that should be an explicit operator decision rather than a silent default.

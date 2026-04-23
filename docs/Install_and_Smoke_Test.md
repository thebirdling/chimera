# Install and Smoke Test

This guide defines the recommended install paths for Chimera `v0.6.0` and the minimum smoke checks that should pass before release or wrapper integration.

## 1. Install Modes

### 1.1 Standard package install

```bash
pip install .
```

Use this when validating a clean package install.

### 1.2 CLI-first install with `pipx`

```bash
pipx install .
chimera --version
```

This is the recommended path for users who want Chimera as a command-line tool without manually managing a virtual environment.

### 1.3 Editable contributor install

```bash
pip install -e .[dev]
```

Use this for local development and test workflows.

## 2. Minimum Smoke Checks

The portable runtime release expects the following checks to pass:

### 2.1 Version

```bash
chimera --version
```

Expected:

- command returns successfully
- version matches the release tag

### 2.2 Doctor

```bash
chimera doctor
chimera doctor --json
```

Expected:

- runtime diagnostics complete successfully
- JSON envelope is valid

### 2.3 Small run smoke

```bash
chimera run --config chimera.yaml --input auth.csv --output ./chimera_output --json
```

Expected:

- stable JSON envelope is printed
- `chimera_run_report.json` is written
- `artifact_manifest.json` is written

### 2.4 Small benchmark smoke

```bash
chimera bench --config chimera.yaml --input auth.csv --injection-type session_hijack --output ./chimera_bench --json
```

Expected:

- stable benchmark envelope is printed
- `bench_report.json` is written
- Markdown benchmark report is written
- `artifact_manifest.json` is written

## 3. Optional Native Check

Rust/native support remains optional.

Use:

```bash
chimera doctor --json
```

Expected:

- native kernels may report available acceleration details or explicit Python fallback behavior
- absence of native acceleration must not block the default install path
- optional native-kernel absence should still be treated as a healthy install when Python fallbacks are active

## 4. Verified Model Check

If validating detection with a trained artifact:

1. train a model with Chimera
2. ensure an integrity manifest exists next to the model
3. run `chimera info --json`
4. run `chimera detect ... --json`

This confirms that the portable runtime contract does not bypass integrity verification.

## 5. Wrapper Readiness Check

Before building the first npm wrapper, confirm:

- JSON envelopes are stable
- artifact manifests are emitted
- `doctor` works in the target environment
- `run` and `bench` work without requiring Rust
- `agent-review` works against runtime artifacts without requiring an external model or network service

That is the actual release gate for the `v0.6.0` portable runtime milestone.

## 6. Pre-Release Hygiene Check

Before tagging or publishing a release, run one final repository hygiene pass:

- confirm `git status --short` only shows intentional source, test, and docs changes
- confirm ignored build output stays ignored, especially `rust/**/target/`, wheel metadata, caches, and native kernel binaries
- confirm no generated Rust artifacts remain tracked in git history
- confirm temporary benchmark and smoke-test output directories are removed from the working tree
- confirm `chimera --version`, `chimera doctor --json`, one `chimera run --json`, and one `chimera agent-review --json` still work on the release candidate
- confirm optional native-kernel absence is reported as healthy Python fallback behavior rather than an install failure

If any generated binary, cache directory, or temporary benchmark output appears in `git status`, clean it before release rather than shipping around it.

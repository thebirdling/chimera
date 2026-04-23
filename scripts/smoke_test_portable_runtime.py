from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _run(command: list[str], cwd: Path) -> dict:
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
    return json.loads(completed.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a portable-runtime smoke test for Chimera v0.6.0."
    )
    parser.add_argument("--input", required=True, help="Path to auth CSV or JSON input.")
    parser.add_argument("--config", default="chimera.yaml", help="Path to Chimera config.")
    parser.add_argument("--output-dir", default="smoke_runtime_output", help="Output directory for run smoke.")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    output_dir = repo_root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    version = subprocess.run(
        [sys.executable, "-m", "chimera.cli", "--version"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    print(version.stdout.strip())

    doctor_env = _run(
        [sys.executable, "-m", "chimera.cli", "doctor", "--config", args.config, "--json"],
        repo_root,
    )
    print(json.dumps(doctor_env, indent=2))

    run_env = _run(
        [
            sys.executable,
            "-m",
            "chimera.cli",
            "run",
            "--config",
            args.config,
            "--input",
            args.input,
            "--output",
            str(output_dir),
            "--json",
        ],
        repo_root,
    )
    print(json.dumps(run_env, indent=2))


if __name__ == "__main__":
    main()

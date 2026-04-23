from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=True,
    )


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    sample_input = repo_root / "tmp_large_auth.csv"

    with tempfile.TemporaryDirectory(prefix="chimera-pkg-smoke-") as tmpdir:
        tmp = Path(tmpdir)
        venv_dir = tmp / "venv"
        output_dir = tmp / "run_out"

        _run([sys.executable, "-m", "venv", str(venv_dir)], cwd=repo_root)
        if sys.platform == "win32":
            py = venv_dir / "Scripts" / "python.exe"
        else:
            py = venv_dir / "bin" / "python"

        _run([str(py), "-m", "pip", "install", str(repo_root)], cwd=repo_root)
        if sys.platform == "win32":
            chimera_cmd = venv_dir / "Scripts" / "chimera.exe"
        else:
            chimera_cmd = venv_dir / "bin" / "chimera"

        version = _run([str(chimera_cmd), "--version"], cwd=repo_root)
        doctor = _run([str(chimera_cmd), "doctor", "--json"], cwd=repo_root)
        run = _run(
            [
                str(chimera_cmd),
                "run",
                "--config",
                "chimera.yaml",
                "--input",
                str(sample_input),
                "--output",
                str(output_dir),
                "--json",
            ],
            cwd=repo_root,
        )
        agent = _run(
            [
                str(chimera_cmd),
                "agent-review",
                "--input",
                str(output_dir / "chimera_run_report.json"),
                "--json",
            ],
            cwd=repo_root,
        )

        summary = {
            "version": version.stdout.strip(),
            "doctor": json.loads(doctor.stdout),
            "run": json.loads(run.stdout),
            "agent_review": json.loads(agent.stdout),
            "temp_dir": str(tmp),
        }
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

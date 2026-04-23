"""
Build helper for the optional Rust graph kernels.

Usage:
    python chimera/_native/build_rust.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent.resolve()
CRATE_DIR = HERE.parent.parent / "rust" / "graph_kernels"


def _cleanup_old_versioned_artifacts() -> None:
    for pattern in ("rust_graph_kernels-*.dll", "librust_graph_kernels-*.so", "librust_graph_kernels-*.dylib"):
        for artifact in HERE.glob(pattern):
            try:
                artifact.unlink()
            except OSError:
                pass


def main() -> int:
    if not CRATE_DIR.exists():
        print("[rust-build] Rust crate not found:", CRATE_DIR)
        return 1

    cmd = ["cargo", "build", "--release"]
    result = subprocess.run(cmd, cwd=CRATE_DIR)
    if result.returncode != 0:
        return result.returncode

    target_dir = CRATE_DIR / "target" / "release"
    candidates = [
        target_dir / "rust_graph_kernels.dll",
        target_dir / "librust_graph_kernels.so",
        target_dir / "librust_graph_kernels.dylib",
    ]
    copied = False
    _cleanup_old_versioned_artifacts()
    for candidate in candidates:
        if candidate.exists():
            destination = HERE / candidate.name
            try:
                shutil.copy2(candidate, destination)
            except PermissionError:
                versioned_destination = HERE / f"{candidate.stem}-{int(time.time())}{candidate.suffix}"
                shutil.copy2(candidate, versioned_destination)
                print(
                    f"[rust-build] Active native library was locked; copied {candidate.name} "
                    f"to {versioned_destination.name} instead"
                )
            else:
                print(f"[rust-build] Copied {candidate.name} to {HERE}")
            copied = True
    if not copied:
        print("[rust-build] Build succeeded but no cdylib artifact was found.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

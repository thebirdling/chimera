"""
Build helper for the optional Rust graph kernels.

Usage:
    python chimera/_native/build_rust.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent.resolve()
CRATE_DIR = HERE.parent.parent / "rust" / "graph_kernels"


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
    for candidate in candidates:
        if candidate.exists():
            shutil.copy2(candidate, HERE / candidate.name)
            print(f"[rust-build] Copied {candidate.name} to {HERE}")
            copied = True
    if not copied:
        print("[rust-build] Build succeeded but no cdylib artifact was found.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

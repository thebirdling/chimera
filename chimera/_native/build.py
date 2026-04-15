"""
chimera/_native/build.py — Build script for the native distance extension.

Compiles distances.c into a shared library (.pyd on Windows, .so on Linux/macOS)
using cffi. The compiled library is placed in chimera/_native/ and imported
from chimera/detectors/lof.py via ctypes with a graceful numpy fallback.

Usage
-----
    python chimera/_native/build.py

Or install the whole package (build is triggered automatically):
    pip install -e .

CBLAS detection
---------------
The script attempts to locate OpenBLAS (bundled with numpy) and enables
the CBLAS Gram matrix path if found. If not found, the naive O(n²d) fallback
is compiled — still correct, just slower for large n.

Windows note
------------
On Windows, MSVC is required for the CBLAS path (cl.exe must be in PATH).
The naive path compiles with MinGW/GCC as well via cffi's default compiler.
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent.resolve()
SRC = HERE / "distances.c"
OUT_DIR = HERE


def detect_numpy_blas_include() -> tuple[list[str], list[str], bool]:
    """Attempt to find the CBLAS headers bundled with numpy.

    Returns
    -------
    tuple[list[str], list[str], bool]
        (include_dirs, library_dirs, cblas_available)
    """
    try:
        import numpy as np
        np_include = np.get_include()
        # numpy bundles OpenBLAS includes under numpy/core/include/numpy/
        # and sometimes cblas.h is in the same location as numpy's own headers.
        blas_include = str(Path(np_include).parent.parent / "core" / "include")
        return [np_include, blas_include], [], True
    except (ImportError, OSError):
        return [], [], False


def build_cffi() -> bool:
    """Build using cffi (preferred; handles Windows MSVC and Linux GCC/Clang)."""
    try:
        from cffi import FFI
    except ImportError:
        print("[build] cffi not available. Install with: pip install cffi")
        return False

    include_dirs, library_dirs, has_cblas = detect_numpy_blas_include()

    ffi = FFI()
    ffi.cdef("""
        void euclidean_distances(const double *X, int n, int d, double *out);
    """)

    extra_compile_args: list[str] = []
    define_macros: list[tuple[str, str]] = []
    libraries: list[str] = []

    if has_cblas:
        define_macros.append(("USE_CBLAS", "1"))
        if platform.system() == "Windows":
            # Try to link against numpy's own BLAS (openblas.lib or blas.lib)
            np_lib = Path(sys.prefix) / "Library" / "lib"
            if np_lib.exists():
                library_dirs.append(str(np_lib))
            libraries.append("blas")
            extra_compile_args.append("/O2")
        else:
            libraries.append("blas")
            extra_compile_args += ["-O3", "-march=native"]

    ffi.set_source(
        "chimera._native._distances",
        f'#include "{SRC}"',
        sources=[str(SRC)],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
        define_macros=define_macros,
        extra_compile_args=extra_compile_args,
    )

    try:
        ffi.compile(tmpdir=str(OUT_DIR), verbose=True)
        print("[build] cffi build successful.")
        return True
    except Exception as e:
        print(f"[build] cffi build failed: {e}")
        return False


def build_ctypes_manual() -> bool:
    """Manual compile fallback using subprocess (GCC/MSVC directly)."""
    system = platform.system()
    if system == "Windows":
        out_name = OUT_DIR / "_distances_ctypes.dll"
        cmd = ["cl", "/LD", "/O2", str(SRC), f"/Fe{out_name}"]
    else:
        out_name = OUT_DIR / "_distances_ctypes.so"
        cmd = ["gcc", "-O3", "-march=native", "-shared", "-fPIC",
               "-lm", str(SRC), "-o", str(out_name)]

    print(f"[build] Attempting manual compile: {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[build] Manual compile succeeded: {out_name.name}")
        return True
    else:
        print(f"[build] Manual compile failed:\n{result.stderr}")
        return False


if __name__ == "__main__":
    print("[build] Building chimera._native distances extension…")
    success = build_cffi() or build_ctypes_manual()
    if success:
        print("[build] Done. Fast distance computation enabled.")
    else:
        print(
            "[build] WARNING: Native extension could not be compiled.\n"
            "         Chimera will fall back to numpy for distance computation.\n"
            "         Core detection is unaffected; only LOF is slower at large n."
        )
        sys.exit(0)  # Non-fatal — never block installation

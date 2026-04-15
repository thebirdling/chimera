"""
chimera._native — C extension loader for fast distance computation.

Attempts to import the compiled cffi extension. Falls back to a
numpy-based implementation that is correct but ~3-5x slower for
dense matrices at n > 5,000.

Never import this module unconditionally in hot paths — always guard
with the _NATIVE_DIST flag:

    from chimera._native import euclidean_distances, NATIVE_AVAILABLE
    if NATIVE_AVAILABLE:
        dist_matrix = euclidean_distances(X)
    else:
        dist_matrix = _numpy_euclidean(X)
"""
from __future__ import annotations

import ctypes
import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

NATIVE_AVAILABLE: bool = False
_lib = None

# Attempt 1: cffi-compiled extension
try:
    from chimera._native import _distances  # type: ignore[import]
    _ffi_available = True
    NATIVE_AVAILABLE = True
    logger.debug("[native] cffi distance extension loaded.")
except ImportError:
    _ffi_available = False

# Attempt 2: ctypes compiled .dll / .so fallback
if not _ffi_available:
    _native_dir = Path(__file__).parent
    for candidate in ["_distances_ctypes.dll", "_distances_ctypes.so", "_distances_ctypes.dylib"]:
        _lib_path = _native_dir / candidate
        if _lib_path.exists():
            try:
                _lib = ctypes.CDLL(str(_lib_path))
                _lib.euclidean_distances.argtypes = [
                    ctypes.POINTER(ctypes.c_double),  # X
                    ctypes.c_int,                     # n
                    ctypes.c_int,                     # d
                    ctypes.POINTER(ctypes.c_double),  # out
                ]
                _lib.euclidean_distances.restype = None
                NATIVE_AVAILABLE = True
                logger.debug("[native] ctypes distance library loaded: %s", candidate)
                break
            except OSError as e:
                logger.debug("[native] ctypes load failed for %s: %s", candidate, e)

if not NATIVE_AVAILABLE:
    logger.info(
        "[native] Native distance extension not available. "
        "Using numpy fallback. Run 'python chimera/_native/build.py' to compile."
    )


# ------------------------------------------------------------------
# Unified API — called from detectors/lof.py
# ------------------------------------------------------------------

def euclidean_distances(X: np.ndarray) -> np.ndarray:
    """Compute the n×n pairwise Euclidean distance matrix for X (n, d).

    Uses the native CBLAS extension if compiled; falls back to numpy.

    Parameters
    ----------
    X:
        Row-major 2-D array of shape (n, d).

    Returns
    -------
    np.ndarray
        Symmetric distance matrix of shape (n, n).
    """
    X = np.asarray(X, dtype=np.float64, order="C")
    n, d = X.shape

    if NATIVE_AVAILABLE:
        if _ffi_available:
            return _cffi_euclidean(X, n, d)
        elif _lib is not None:
            return _ctypes_euclidean(X, n, d)

    return _numpy_euclidean(X)


def _cffi_euclidean(X: np.ndarray, n: int, d: int) -> np.ndarray:
    out = np.zeros((n, n), dtype=np.float64, order="C")
    _distances.lib.euclidean_distances(
        _distances.ffi.cast("double *", X.ctypes.data),
        n, d,
        _distances.ffi.cast("double *", out.ctypes.data),
    )
    return out


def _ctypes_euclidean(X: np.ndarray, n: int, d: int) -> np.ndarray:
    out = np.zeros((n, n), dtype=np.float64, order="C")
    _lib.euclidean_distances(
        X.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
        ctypes.c_int(n),
        ctypes.c_int(d),
        out.ctypes.data_as(ctypes.POINTER(ctypes.c_double)),
    )
    return out


def _numpy_euclidean(X: np.ndarray) -> np.ndarray:
    """Pure numpy Gram matrix trick — same algorithm, no C required."""
    # G = X @ X.T
    G = X @ X.T
    norms = np.diag(G)
    d2 = norms[:, None] + norms[None, :] - 2.0 * G
    np.clip(d2, 0.0, None, out=d2)
    return np.sqrt(d2)

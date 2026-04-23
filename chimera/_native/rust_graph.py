"""
chimera._native.rust_graph - Optional Rust graph kernels for identity research.

The first kernel focuses on integer-encoded pair overlap counts, which are
useful for identity graph features such as shared IP+ASN infrastructure bursts.
If the Rust cdylib is not present, the module falls back to a pure-Python
implementation with identical semantics.
"""

from __future__ import annotations

import ctypes
import logging
import re
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

RUST_GRAPH_AVAILABLE = False
RUST_GRAPH_BURST_AVAILABLE = False
RUST_GRAPH_BURST_VOLUME_AVAILABLE = False
RUST_GRAPH_SEQUENCE_AVAILABLE = False
_graph_lib = None

_NATIVE_DIR = Path(__file__).parent
_ALLOWED_NATIVE_PATTERNS = (
    re.compile(r"^rust_graph_kernels(?:-\d+)?\.dll$"),
    re.compile(r"^librust_graph_kernels(?:-\d+)?\.so$"),
    re.compile(r"^librust_graph_kernels(?:-\d+)?\.dylib$"),
)


def _is_allowed_native_artifact_name(name: str) -> bool:
    return any(pattern.match(name) for pattern in _ALLOWED_NATIVE_PATTERNS)


def _native_candidate_paths() -> list[Path]:
    exact_names = [
        _NATIVE_DIR / "rust_graph_kernels.dll",
        _NATIVE_DIR / "librust_graph_kernels.so",
        _NATIVE_DIR / "librust_graph_kernels.dylib",
    ]
    versioned = sorted(
        [
            path
            for path in _NATIVE_DIR.iterdir()
            if path.is_file() and _is_allowed_native_artifact_name(path.name) and path not in exact_names
        ],
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return [path for path in exact_names if path.exists()] + versioned


_candidate_paths = _native_candidate_paths()
for lib_path in _candidate_paths:
    candidate = lib_path.name
    if lib_path.exists():
        try:
            _graph_lib = ctypes.CDLL(str(lib_path))
            _graph_lib.shared_pair_prior_counts.argtypes = [
                ctypes.POINTER(ctypes.c_longlong),
                ctypes.POINTER(ctypes.c_longlong),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_longlong),
            ]
            _graph_lib.shared_pair_prior_counts.restype = None
            RUST_GRAPH_AVAILABLE = True
            try:
                _graph_lib.shared_pair_recent_peer_counts.argtypes = [
                    ctypes.POINTER(ctypes.c_longlong),
                    ctypes.POINTER(ctypes.c_longlong),
                    ctypes.POINTER(ctypes.c_longlong),
                    ctypes.c_size_t,
                    ctypes.c_longlong,
                    ctypes.POINTER(ctypes.c_longlong),
                ]
                _graph_lib.shared_pair_recent_peer_counts.restype = None
                globals()["RUST_GRAPH_BURST_AVAILABLE"] = True
            except AttributeError:
                logger.debug(
                    "[rust-graph] Burst kernel symbol unavailable in %s; falling back to Python.",
                    candidate,
                )
            try:
                _graph_lib.shared_pair_recent_event_counts.argtypes = [
                    ctypes.POINTER(ctypes.c_longlong),
                    ctypes.POINTER(ctypes.c_longlong),
                    ctypes.c_size_t,
                    ctypes.c_longlong,
                    ctypes.POINTER(ctypes.c_longlong),
                ]
                _graph_lib.shared_pair_recent_event_counts.restype = None
                globals()["RUST_GRAPH_BURST_VOLUME_AVAILABLE"] = True
            except AttributeError:
                logger.debug(
                    "[rust-graph] Burst-volume kernel symbol unavailable in %s; falling back to Python.",
                    candidate,
                )
            try:
                _graph_lib.ordered_takeover_sequence_progress.argtypes = [
                    ctypes.POINTER(ctypes.c_longlong),
                    ctypes.POINTER(ctypes.c_longlong),
                    ctypes.POINTER(ctypes.c_longlong),
                    ctypes.c_size_t,
                    ctypes.c_longlong,
                    ctypes.POINTER(ctypes.c_longlong),
                ]
                _graph_lib.ordered_takeover_sequence_progress.restype = None
                globals()["RUST_GRAPH_SEQUENCE_AVAILABLE"] = True
            except AttributeError:
                logger.debug(
                    "[rust-graph] Sequence kernel symbol unavailable in %s; falling back to Python.",
                    candidate,
                )
            logger.debug("[rust-graph] Loaded Rust graph kernels: %s", candidate)
            break
        except OSError as exc:
            logger.debug("[rust-graph] Failed to load %s: %s", candidate, exc)


def shared_pair_prior_counts(
    pair_codes: np.ndarray,
    user_codes: np.ndarray,
) -> np.ndarray:
    """
    Count how many distinct prior users have already used each pair code.

    Parameters
    ----------
    pair_codes:
        1-D integer array. Each value is an encoded infrastructure pair
        such as IP+ASN, IP+device, or device+ASN.
    user_codes:
        1-D integer array aligned with ``pair_codes``.

    Returns
    -------
    np.ndarray
        Prior distinct-user counts for each position.
    """
    pair_codes = np.asarray(pair_codes, dtype=np.int64, order="C")
    user_codes = np.asarray(user_codes, dtype=np.int64, order="C")
    if pair_codes.shape != user_codes.shape:
        raise ValueError("pair_codes and user_codes must have the same shape")

    out = np.zeros(pair_codes.shape[0], dtype=np.int64, order="C")
    if RUST_GRAPH_AVAILABLE and _graph_lib is not None:
        _graph_lib.shared_pair_prior_counts(
            pair_codes.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            user_codes.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            ctypes.c_size_t(pair_codes.shape[0]),
            out.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
        )
        return out

    seen: dict[int, set[int]] = {}
    for idx, (pair_code, user_code) in enumerate(zip(pair_codes, user_codes)):
        prior_users = seen.setdefault(int(pair_code), set())
        out[idx] = len(prior_users)
        prior_users.add(int(user_code))
    return out


def shared_pair_recent_peer_counts(
    pair_codes: np.ndarray,
    user_codes: np.ndarray,
    timestamps: np.ndarray,
    *,
    window_seconds: int,
) -> np.ndarray:
    """
    Count distinct prior peer users sharing the same pair within a local window.

    The computation is causal: only prior events inside ``window_seconds`` are
    considered, and the current user's own prior events are excluded.
    """
    pair_codes = np.asarray(pair_codes, dtype=np.int64, order="C")
    user_codes = np.asarray(user_codes, dtype=np.int64, order="C")
    timestamps = np.asarray(timestamps, dtype=np.int64, order="C")
    if not (pair_codes.shape == user_codes.shape == timestamps.shape):
        raise ValueError("pair_codes, user_codes, and timestamps must have the same shape")

    out = np.zeros(pair_codes.shape[0], dtype=np.int64, order="C")
    if RUST_GRAPH_BURST_AVAILABLE and _graph_lib is not None:
        _graph_lib.shared_pair_recent_peer_counts(
            pair_codes.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            user_codes.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            timestamps.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            ctypes.c_size_t(pair_codes.shape[0]),
            ctypes.c_longlong(int(window_seconds)),
            out.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
        )
        return out

    window_seconds = int(window_seconds)
    left = 0
    pair_user_counts: dict[int, dict[int, int]] = {}
    for idx, (pair_code, user_code, ts) in enumerate(zip(pair_codes, user_codes, timestamps)):
        current_ts = int(ts)
        while left < idx and current_ts - int(timestamps[left]) > window_seconds:
            expired_pair = int(pair_codes[left])
            expired_user = int(user_codes[left])
            user_counts = pair_user_counts.get(expired_pair)
            if user_counts is not None:
                remaining = user_counts.get(expired_user, 0) - 1
                if remaining > 0:
                    user_counts[expired_user] = remaining
                else:
                    user_counts.pop(expired_user, None)
                if not user_counts:
                    pair_user_counts.pop(expired_pair, None)
            left += 1

        current_pair = int(pair_code)
        current_user = int(user_code)
        user_counts = pair_user_counts.get(current_pair, {})
        out[idx] = max(len(user_counts) - (1 if current_user in user_counts else 0), 0)
        mutable_counts = pair_user_counts.setdefault(current_pair, {})
        mutable_counts[current_user] = mutable_counts.get(current_user, 0) + 1
    return out


def shared_pair_recent_event_counts(
    pair_codes: np.ndarray,
    timestamps: np.ndarray,
    *,
    window_seconds: int,
) -> np.ndarray:
    """Count prior events sharing the same pair code within a local causal window."""
    pair_codes = np.asarray(pair_codes, dtype=np.int64, order="C")
    timestamps = np.asarray(timestamps, dtype=np.int64, order="C")
    if pair_codes.shape != timestamps.shape:
        raise ValueError("pair_codes and timestamps must have the same shape")

    out = np.zeros(pair_codes.shape[0], dtype=np.int64, order="C")
    if RUST_GRAPH_BURST_VOLUME_AVAILABLE and _graph_lib is not None:
        _graph_lib.shared_pair_recent_event_counts(
            pair_codes.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            timestamps.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            ctypes.c_size_t(pair_codes.shape[0]),
            ctypes.c_longlong(int(window_seconds)),
            out.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
        )
        return out

    window_seconds = int(window_seconds)
    left = 0
    pair_counts: dict[int, int] = {}
    for idx, (pair_code, ts) in enumerate(zip(pair_codes, timestamps)):
        current_ts = int(ts)
        while left < idx and current_ts - int(timestamps[left]) > window_seconds:
            expired_pair = int(pair_codes[left])
            remaining = pair_counts.get(expired_pair, 0) - 1
            if remaining > 0:
                pair_counts[expired_pair] = remaining
            else:
                pair_counts.pop(expired_pair, None)
            left += 1

        current_pair = int(pair_code)
        out[idx] = pair_counts.get(current_pair, 0)
        pair_counts[current_pair] = pair_counts.get(current_pair, 0) + 1
    return out


def ordered_takeover_sequence_progress(
    user_codes: np.ndarray,
    stage_codes: np.ndarray,
    timestamps: np.ndarray,
    *,
    window_seconds: int,
) -> np.ndarray:
    """
    Track causal progression through an ordered takeover sequence per user.

    Stage codes are expected to represent:
    1 = login or authentication establishment
    2 = session continuation or token reuse
    3 = privileged follow-on activity
    """
    user_codes = np.asarray(user_codes, dtype=np.int64, order="C")
    stage_codes = np.asarray(stage_codes, dtype=np.int64, order="C")
    timestamps = np.asarray(timestamps, dtype=np.int64, order="C")
    if not (user_codes.shape == stage_codes.shape == timestamps.shape):
        raise ValueError("user_codes, stage_codes, and timestamps must have the same shape")

    out = np.zeros(user_codes.shape[0], dtype=np.int64, order="C")
    if RUST_GRAPH_SEQUENCE_AVAILABLE and _graph_lib is not None:
        _graph_lib.ordered_takeover_sequence_progress(
            user_codes.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            stage_codes.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            timestamps.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
            ctypes.c_size_t(user_codes.shape[0]),
            ctypes.c_longlong(int(window_seconds)),
            out.ctypes.data_as(ctypes.POINTER(ctypes.c_longlong)),
        )
        return out

    stage1_ts: dict[int, int] = {}
    stage2_ts: dict[int, int] = {}
    window_seconds = int(window_seconds)

    for idx, (user_code, stage_code, ts) in enumerate(
        zip(user_codes, stage_codes, timestamps)
    ):
        user = int(user_code)
        stage = int(stage_code)
        current_ts = int(ts)
        if stage == 1:
            stage1_ts[user] = current_ts
            stage2_ts.pop(user, None)
        elif stage == 2:
            prior_stage1 = stage1_ts.get(user)
            if prior_stage1 is not None and current_ts - prior_stage1 <= window_seconds:
                out[idx] = 1
                stage2_ts[user] = current_ts
            else:
                stage2_ts.pop(user, None)
        elif stage == 3:
            prior_stage1 = stage1_ts.get(user)
            prior_stage2 = stage2_ts.get(user)
            if (
                prior_stage1 is not None
                and prior_stage2 is not None
                and prior_stage2 >= prior_stage1
                and current_ts - prior_stage2 <= window_seconds
                and current_ts - prior_stage1 <= window_seconds
            ):
                out[idx] = 2
    return out

import numpy as np

from chimera._native.rust_graph import (
    _is_allowed_native_artifact_name,
    ordered_takeover_sequence_progress,
    shared_pair_prior_counts,
    shared_pair_recent_event_counts,
    shared_pair_recent_peer_counts,
)


class TestRustGraphFallback:
    def test_shared_pair_prior_counts(self):
        pair_codes = np.array([10, 10, 12, 10, 12], dtype=np.int64)
        user_codes = np.array([1, 2, 2, 1, 3], dtype=np.int64)

        counts = shared_pair_prior_counts(pair_codes, user_codes)

        assert counts.tolist() == [0, 1, 0, 2, 1]

    def test_shared_pair_recent_peer_counts(self):
        pair_codes = np.array([10, 10, 10, 12, 10], dtype=np.int64)
        user_codes = np.array([1, 1, 2, 3, 4], dtype=np.int64)
        timestamps = np.array([0, 20, 30, 31, 100], dtype=np.int64)

        counts = shared_pair_recent_peer_counts(
            pair_codes,
            user_codes,
            timestamps,
            window_seconds=45,
        )

        assert counts.tolist() == [0, 0, 1, 0, 0]

    def test_shared_pair_recent_event_counts(self):
        pair_codes = np.array([10, 10, 12, 10, 12], dtype=np.int64)
        timestamps = np.array([0, 20, 21, 40, 90], dtype=np.int64)

        counts = shared_pair_recent_event_counts(
            pair_codes,
            timestamps,
            window_seconds=45,
        )

        assert counts.tolist() == [0, 1, 0, 2, 0]

    def test_ordered_takeover_sequence_progress(self):
        user_codes = np.array([1, 1, 1, 2, 2], dtype=np.int64)
        stage_codes = np.array([1, 2, 3, 2, 3], dtype=np.int64)
        timestamps = np.array([0, 10, 20, 5, 10], dtype=np.int64)

        counts = ordered_takeover_sequence_progress(
            user_codes,
            stage_codes,
            timestamps,
            window_seconds=30,
        )

        assert counts.tolist() == [0, 1, 2, 0, 0]

    def test_native_artifact_name_allowlist(self):
        assert _is_allowed_native_artifact_name("rust_graph_kernels.dll")
        assert _is_allowed_native_artifact_name("rust_graph_kernels-123.dll")
        assert not _is_allowed_native_artifact_name("rust_graph_kernels-evil.dll")
        assert not _is_allowed_native_artifact_name("totally_different.dll")

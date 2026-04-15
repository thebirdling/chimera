"""
tests/test_engine.py — Formal pytest suite for chimera.engine v0.3.

Run with:
    pytest tests/test_engine.py -v
    pytest tests/test_engine.py -v --tb=short
"""
from __future__ import annotations

import numpy as np
import pytest


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def rng():
    return np.random.default_rng(42)


@pytest.fixture(scope="module")
def normal_scores(rng):
    """400 clean scores centred around 0."""
    return rng.normal(loc=0.0, scale=1.0, size=400)


@pytest.fixture(scope="module")
def two_model_scores(rng):
    """Dict of two model score arrays for ensemble tests."""
    return {
        "if": rng.normal(loc=-0.3, scale=0.2, size=300),
        "lof": rng.normal(loc=0.5, scale=0.3, size=300),
    }


# ── normalizer ────────────────────────────────────────────────────


class TestScoreNormalizer:
    def test_minmax_bounds(self, normal_scores):
        from chimera.engine.normalizer import ScoreNormalizer
        norm = ScoreNormalizer(strategy="minmax")
        out = norm.fit_transform("if", normal_scores)
        assert out.min() >= 0.0 - 1e-9
        assert out.max() <= 1.0 + 1e-9

    def test_quantile_bounds(self, normal_scores):
        from chimera.engine.normalizer import ScoreNormalizer
        norm = ScoreNormalizer(strategy="quantile", quantile_range=(0.05, 0.95))
        out = norm.fit_transform("if", normal_scores)
        # Most values should be in [0, 1]; clipping allows slightly outside
        assert np.percentile(out, 5) >= -0.1
        assert np.percentile(out, 95) <= 1.1

    def test_collapse_guard_returns_half(self):
        from chimera.engine.normalizer import ScoreNormalizer
        norm = ScoreNormalizer()
        out = norm.fit_transform("if", np.ones(60) * 7.7)
        assert np.allclose(out, 0.5), f"Expected 0.5 for collapsed scores, got {out[:3]}"

    def test_insufficient_data_raises(self):
        from chimera.engine.normalizer import ScoreNormalizer, InsufficientDataError
        norm = ScoreNormalizer()
        with pytest.raises(InsufficientDataError):
            norm.fit("if", np.ones(5))

    def test_multiple_models(self, rng):
        from chimera.engine.normalizer import ScoreNormalizer
        norm = ScoreNormalizer()
        s1 = rng.uniform(0, 10, 50)
        s2 = rng.uniform(-5, 5, 50)
        o1 = norm.fit_transform("if", s1)
        o2 = norm.fit_transform("lof", s2)
        assert o1.shape == (50,)
        assert o2.shape == (50,)
        # Transform on already-fitted model should match
        o1b = norm.transform("if", s1)
        assert np.allclose(o1, o1b)

    def test_transform_raises_when_not_fitted(self):
        from chimera.engine.normalizer import ScoreNormalizer
        norm = ScoreNormalizer()
        with pytest.raises(KeyError):
            norm.transform("unfitted_model", np.ones(30))

    def test_low_variance_guard(self, rng):
        from chimera.engine.normalizer import ScoreNormalizer
        norm = ScoreNormalizer(low_variance_threshold=0.1)
        # Scores with very little variance
        scores = rng.normal(0, 0.001, 60)
        out = norm.fit_transform("if", scores)
        assert np.all(np.isfinite(out))


# ── voter ─────────────────────────────────────────────────────────


class TestEnsembleVoter:
    def test_mean_strategy(self):
        from chimera.engine.voter import EnsembleVoter
        voter = EnsembleVoter(strategy="mean")
        scores = {"a": np.array([0.2, 0.8]), "b": np.array([0.4, 0.6])}
        result = voter.vote(scores)
        assert np.allclose(result, [0.3, 0.7])

    def test_median_strategy(self):
        from chimera.engine.voter import EnsembleVoter
        voter = EnsembleVoter(strategy="median")
        scores = {"a": np.array([0.1, 0.9]), "b": np.array([0.5, 0.5]), "c": np.array([0.3, 0.7])}
        result = voter.vote(scores)
        assert np.allclose(result, [0.3, 0.7])

    def test_trimmed_mean(self, rng):
        from chimera.engine.voter import EnsembleVoter
        voter = EnsembleVoter(strategy="trimmed_mean", trim_fraction=0.2)
        scores = {f"m{i}": rng.uniform(0, 1, 100) for i in range(5)}
        result = voter.vote(scores)
        assert result.shape == (100,)
        assert np.all(result >= 0.0) and np.all(result <= 1.0)

    def test_weighted_strategy(self):
        from chimera.engine.voter import EnsembleVoter
        voter = EnsembleVoter(
            strategy="weighted",
            weights={"a": 0.9, "b": 0.1},
        )
        scores = {"a": np.array([1.0, 0.0]), "b": np.array([0.0, 1.0])}
        result = voter.vote(scores)
        # Should be dominated by model 'a'
        assert result[0] > result[1]

    def test_entropy_shape(self, two_model_scores):
        from chimera.engine.voter import EnsembleVoter
        voter = EnsembleVoter()
        H = voter.disagreement_entropy(two_model_scores)
        assert H.shape == (300,)
        assert np.all(H >= 0.0)
        assert np.all(np.isfinite(H))

    def test_score_variance(self, two_model_scores):
        from chimera.engine.voter import EnsembleVoter
        voter = EnsembleVoter()
        V = voter.score_variance(two_model_scores)
        assert V.shape == (300,)
        assert np.all(V >= 0.0)

    def test_empty_scores_raises(self):
        from chimera.engine.voter import EnsembleVoter
        voter = EnsembleVoter()
        with pytest.raises(ValueError):
            voter.vote({})

    def test_unknown_strategy_raises(self):
        from chimera.engine.voter import EnsembleVoter
        with pytest.raises(ValueError):
            EnsembleVoter(strategy="unicorn")


# ── threshold ─────────────────────────────────────────────────────


class TestDynamicThreshold:
    def test_fit_percentile(self, normal_scores):
        from chimera.engine.threshold import DynamicThreshold
        dt = DynamicThreshold(contamination=0.10)
        tau = dt.fit(normal_scores)
        expected = float(np.percentile(normal_scores, 90.0))
        assert abs(tau - expected) < 1e-9

    def test_update_returns_delta(self, rng):
        from chimera.engine.threshold import DynamicThreshold
        dt = DynamicThreshold(contamination=0.05)
        dt.fit(rng.uniform(0, 1, 500))
        new_tau, delta = dt.update(rng.uniform(1, 2, 500))  # shifted
        assert isinstance(delta, float)
        assert delta >= 0.0

    def test_drift_history_grows(self, rng):
        from chimera.engine.threshold import DynamicThreshold
        dt = DynamicThreshold(contamination=0.05)
        dt.fit(rng.uniform(0, 1, 200))
        for _ in range(3):
            dt.update(rng.uniform(0, 1, 200))
        assert len(dt.drift_history) == 3

    def test_instability_metric_nonnegative(self, rng):
        from chimera.engine.threshold import DynamicThreshold
        dt = DynamicThreshold()
        dt.fit(rng.uniform(0, 1, 200))
        dt.update(rng.uniform(0, 1, 200))
        assert dt.instability_metric >= 0.0

    def test_insufficient_data_raises(self):
        from chimera.engine.threshold import DynamicThreshold, InsufficientDataError
        dt = DynamicThreshold()
        with pytest.raises(InsufficientDataError):
            dt.fit(np.array([0.1, 0.2]))


# ── pipeline ──────────────────────────────────────────────────────


class TestEnginePipeline:
    def test_basic_end_to_end(self, two_model_scores):
        from chimera.engine.pipeline import EnginePipeline, ScoreResult
        pipeline = EnginePipeline(contamination=0.05)
        pipeline.fit(two_model_scores)
        result = pipeline.score(two_model_scores)
        assert isinstance(result, ScoreResult)
        assert result.ensemble_scores.shape == (300,)
        assert result.anomaly_mask.dtype == bool
        assert 0.0 <= result.threshold <= 1.0

    def test_from_config(self, two_model_scores):
        from chimera.engine.pipeline import EnginePipeline
        config = {
            "normalization": {"strategy": "quantile", "quantile_range": [0.05, 0.95]},
            "ensemble": {"voting_strategy": "median"},
            "threshold": {"contamination": 0.1},
        }
        pipeline = EnginePipeline.from_config(config)
        pipeline.fit(two_model_scores)
        result = pipeline.score(two_model_scores)
        assert result.ensemble_scores.shape == (300,)

    def test_anomaly_rate_matches_contamination(self, rng):
        from chimera.engine.pipeline import EnginePipeline
        # With contamination=0.10, expect ~10% flagged
        scores = {"if": rng.uniform(0, 1, 500), "lof": rng.uniform(0, 1, 500)}
        pipeline = EnginePipeline(contamination=0.10)
        pipeline.fit(scores)
        result = pipeline.score(scores)
        anomaly_rate = result.anomaly_mask.mean()
        assert 0.05 < anomaly_rate < 0.20, f"Anomaly rate {anomaly_rate:.3f} out of expected range"

    def test_not_fitted_raises(self, two_model_scores):
        from chimera.engine.pipeline import EnginePipeline
        pipeline = EnginePipeline()
        with pytest.raises(RuntimeError):
            pipeline.score(two_model_scores)

    def test_score_result_has_disaggrement_entropy(self, two_model_scores):
        from chimera.engine.pipeline import EnginePipeline
        pipeline = EnginePipeline()
        pipeline.fit(two_model_scores)
        result = pipeline.score(two_model_scores)
        assert result.disagreement_entropy.shape == (300,)
        assert np.all(result.disagreement_entropy >= 0.0)

    def test_takeover_hard_floor_requires_support_signal(self):
        from chimera.engine.pipeline import EnginePipeline

        identity_takeover = np.array([0.2] * 30, dtype=float)
        identity_takeover[10] = 0.95
        identity_takeover[20] = 0.95
        identity_takeover_support = np.array([0.2] * 30, dtype=float)
        identity_takeover_support[10] = 0.1
        identity_takeover_support[20] = 0.9
        lof = np.array([0.2] * 30, dtype=float)
        scores = {
            "identity_takeover": identity_takeover,
            "identity_takeover_support": identity_takeover_support,
            "lof": lof,
        }
        pipeline = EnginePipeline(
            contamination=0.34,
            identity_hard_floor_enabled=True,
            identity_hard_floor_model="identity_takeover",
            identity_hard_floor=0.8,
            identity_hard_floor_support_model="identity_takeover_support",
            identity_hard_floor_support_threshold=0.5,
        )
        pipeline.fit(scores)
        result = pipeline.score(scores)

        assert float(result.ensemble_scores[10]) < 1.0
        assert bool(result.anomaly_mask[20]) is True
        assert float(result.ensemble_scores[20]) == 1.0
        assert result.hard_floor_hits >= 1


# ── temporal ──────────────────────────────────────────────────────


class TestTemporalFeatures:
    def test_hour_cyclic_range(self):
        from chimera.engine.temporal import encode_hour_cyclic
        hours = np.linspace(0, 23.99, 1000)
        s, c = encode_hour_cyclic(hours)
        assert np.all(s >= -1.0 - 1e-9) and np.all(s <= 1.0 + 1e-9)
        assert np.all(c >= -1.0 - 1e-9) and np.all(c <= 1.0 + 1e-9)

    def test_hour_0_eq_hour_24(self):
        from chimera.engine.temporal import encode_hour_cyclic
        s0, c0 = encode_hour_cyclic(np.array([0.0]))
        s24, c24 = encode_hour_cyclic(np.array([24.0]))
        assert np.allclose(s0, s24)
        assert np.allclose(c0, c24)

    def test_dow_cyclic_range(self):
        from chimera.engine.temporal import encode_dow_cyclic
        days = np.arange(7)
        s, c = encode_dow_cyclic(days)
        assert np.all(s >= -1.0 - 1e-9) and np.all(s <= 1.0 + 1e-9)

    def test_von_mises_fit_kappa_positive(self):
        from chimera.engine.temporal import fit_von_mises
        # Concentrated at 9am → should have high kappa
        hours = np.full(30, 9.0) + np.random.default_rng(1).normal(0, 0.1, 30)
        model = fit_von_mises(hours)
        assert model.kappa > 0.5
        assert model.n_samples == 30

    def test_von_mises_cold_start(self):
        from chimera.engine.temporal import fit_von_mises
        # Fewer than _MIN_VM_SAMPLES → flat prior
        model = fit_von_mises(np.array([9.0, 10.0, 11.0]))
        assert model.kappa == 0.0

    def test_von_mises_nll_on_axis(self):
        from chimera.engine.temporal import fit_von_mises, von_mises_nll
        hours = np.full(30, 9.0) + np.random.default_rng(1).normal(0, 0.1, 30)
        model = fit_von_mises(hours)
        # NLL at the typical hour (9am) should be low
        nll_typical = von_mises_nll(9.0, model)
        # NLL at an unusual hour (3am) should be higher
        nll_unusual = von_mises_nll(3.0, model)
        assert nll_unusual > nll_typical

    def test_von_mises_baseline_fit(self):
        from chimera.engine.temporal import VonMisesBaseline
        events = [
            {"user_id": "alice", "timestamp": "2024-01-10T09:00:00"}
            for _ in range(15)
        ] + [
            {"user_id": "bob", "timestamp": "2024-01-10T22:00:00"}
            for _ in range(15)
        ]
        baseline = VonMisesBaseline()
        baseline.fit(events)
        assert baseline.is_fitted("alice")
        assert baseline.is_fitted("bob")
        # Alice logs in at 9am; 3am should be anomalous
        p_alice_normal = baseline.anomaly_prior("alice", 9.0)
        p_alice_unusual = baseline.anomaly_prior("alice", 3.0)
        assert p_alice_unusual > p_alice_normal


# ── streaming ─────────────────────────────────────────────────────


class TestStreamingBuffer:
    def test_threshold_trigger(self):
        from chimera.engine.streaming import StreamingBuffer
        buf = StreamingBuffer(release_threshold=5, timeout_seconds=999)
        results = []
        for i in range(7):
            b = buf.push({"i": i})
            if b:
                results.append(b)
        # First batch should fire at 5 events
        assert len(results) == 1
        assert len(results[0]) == 5

    def test_flush_remainder(self):
        from chimera.engine.streaming import StreamingBuffer
        buf = StreamingBuffer(release_threshold=10, timeout_seconds=999)
        for i in range(3):
            buf.push({"i": i})
        batch = buf.flush()
        assert len(batch) == 3
        assert buf.size == 0

    def test_push_all_yields_batches(self):
        from chimera.engine.streaming import StreamingBuffer
        buf = StreamingBuffer(release_threshold=4, timeout_seconds=999)
        events = [{"i": i} for i in range(11)]
        batches = list(buf.push_all(events))
        total = sum(len(b) for b in batches)
        assert total == 11

    def test_thread_safety(self):
        import threading
        from chimera.engine.streaming import StreamingBuffer
        buf = StreamingBuffer(release_threshold=50, timeout_seconds=999)
        received = []
        lock = threading.Lock()

        def producer(start, n):
            for j in range(start, start + n):
                b = buf.push({"j": j})
                if b:
                    with lock:
                        received.extend(b)

        threads = [threading.Thread(target=producer, args=(i * 20, 20)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        remainder = buf.flush()
        received.extend(remainder)
        assert len(received) == 100


# ── evaluation / injector ─────────────────────────────────────────


class TestInjector:
    BASE_EVENTS = [
        {
            "user_id": "alice",
            "source_ip": "10.0.0.1",
            "timestamp": "2024-01-15T09:00:00",
            "outcome": "success",
        }
        for _ in range(30)
    ]

    @pytest.mark.parametrize(
        "itype",
        [
            "volume_spike",
            "temporal_shift",
            "credential_stuffing",
            "asn_shift",
            "burst_attack",
            "session_hijack",
            "mfa_bypass",
            "low_and_slow",
            "password_spraying",
            "coordinated_campaign",
            "identity_drift",
            "temporal_jitter",
        ],
    )
    def test_injection_types(self, itype):
        from chimera.evaluation.injector import inject
        result = inject(self.BASE_EVENTS, type=itype, magnitude=2.0, window=10, seed=42)
        injected = [e for e in result if e.get("_synthetic")]
        assert len(injected) > 0
        assert all(e["_injection_type"] == itype for e in injected)

    def test_deterministic(self):
        from chimera.evaluation.injector import inject
        r1 = inject(self.BASE_EVENTS, type="burst_attack", seed=7)
        r2 = inject(self.BASE_EVENTS, type="burst_attack", seed=7)
        # Same seed → same injection
        assert len(r1) == len(r2)

    def test_synthetic_tag(self):
        from chimera.evaluation.injector import inject
        result = inject(self.BASE_EVENTS, type="burst_attack", window=5, seed=1)
        for ev in result:
            if ev.get("_synthetic"):
                assert "_injection_type" in ev

    def test_session_hijack_has_ordered_takeover_sequence(self):
        from chimera.evaluation.injector import inject

        result = inject(self.BASE_EVENTS, type="session_hijack", magnitude=2.0, window=10, seed=9)
        injected = [e for e in result if e.get("_synthetic")]

        assert len(injected) >= 8
        assert any(e.get("device_fingerprint", "").startswith("hijacked-") for e in injected)
        assert any(str(e.get("raw_fields", {}).get("token_hash", "")).startswith("tok-") for e in injected)
        assert any(e.get("event_type") == "session_refresh" for e in injected)
        assert any(e.get("event_type") == "privileged_action" for e in injected)
        timestamps = [e["timestamp"] for e in injected]
        assert timestamps == sorted(timestamps)

    def test_coordinated_campaign_reuses_shared_infrastructure(self):
        from chimera.evaluation.injector import inject

        multi_user_events = [
            {
                "user_id": user_id,
                "source_ip": f"10.0.0.{idx + 1}",
                "timestamp": f"2024-01-15T09:{idx:02d}:00",
                "outcome": "success",
            }
            for idx, user_id in enumerate(["alice", "bob", "carol", "dave", "erin"])
        ]
        result = inject(multi_user_events, type="coordinated_campaign", magnitude=2.0, window=10, seed=5)
        injected = [e for e in result if e.get("_synthetic")]

        assert len(injected) >= 6
        assert len({e.get("device_fingerprint") for e in injected}) == 1
        assert len({e.get("asn") for e in injected}) == 1
        assert len({e.get("user_id") for e in injected}) >= 3

    def test_temporal_jitter_moves_events_bidirectionally(self):
        from chimera.evaluation.injector import inject

        result = inject(self.BASE_EVENTS, type="temporal_jitter", magnitude=2.0, window=8, seed=3)
        injected = [e for e in result if e.get("_synthetic")]
        base_ts = self.BASE_EVENTS[0]["timestamp"]

        assert len(injected) > 0
        assert any(e["timestamp"] < base_ts for e in injected)
        assert any(e["timestamp"] > base_ts for e in injected)


# ── evaluation / metrics ──────────────────────────────────────────


class TestRobustnessMetrics:
    def test_sensitivity_curve_length(self, normal_scores):
        from chimera.evaluation.metrics import sensitivity_curve
        curve = sensitivity_curve(normal_scores, (0.01, 0.30), n_steps=10)
        assert len(curve) == 10
        # Contamination values should be ascending
        contams = [c for c, _ in curve]
        assert contams == sorted(contams)

    def test_drift_mean_zero_single_threshold(self, normal_scores):
        from chimera.evaluation.metrics import compute_robustness
        report = compute_robustness(
            ensemble_scores=normal_scores,
            per_model_scores={"if": normal_scores},
            threshold_history=[0.8],  # single point → no diff
        )
        assert report.threshold_drift_mean == 0.0

    def test_report_has_to_dict(self, normal_scores):
        from chimera.evaluation.metrics import compute_robustness
        report = compute_robustness(
            ensemble_scores=normal_scores,
            per_model_scores={"if": normal_scores},
            threshold_history=[0.5, 0.52, 0.49],
        )
        d = report.to_dict()
        assert "threshold_drift_mean" in d
        assert "detection_rate_at_fpr" in d

    def test_detection_rate_with_ground_truth(self):
        from chimera.evaluation.metrics import compute_robustness
        n = 200
        scores = np.linspace(0, 1, n)
        gt = np.zeros(n, dtype=bool)
        gt[-20:] = True  # last 20 are "injected"
        anomaly_mask = scores >= 0.90

        report = compute_robustness(
            ensemble_scores=scores,
            per_model_scores={"if": scores},
            threshold_history=[0.9, 0.91],
            ground_truth_mask=gt,
            anomaly_mask=anomaly_mask,
        )
        assert 0.01 in report.detection_rate_at_fpr
        # Scores are monotonically increasing so injected events (high score) should be found
        assert report.detection_rate_at_fpr[0.10] > 0.0

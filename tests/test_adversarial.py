"""
tests/test_adversarial.py — Adversarial hardening regression tests (v0.4.2).

Covers all 13 security fixes from the red team analysis:

Phase A — Structural Blind Spots
  A1: Bootstrap reset lockout (bootstrap.py)
  A2: Slow behavioral drift evasion (drift_guard.py)
  A3: Multi-signal gate hard bypass (suppression.py)
  A4: Cross-user coordinated attack detection (fleet_monitor.py)

Phase B — Cryptographic Weaknesses
  B1: HMAC manifest tamper detection (integrity.py — covered in test_security.py)
  B2: Genesis block chain integrity (crypto.py — covered in test_security.py)
  B3: Import injection prevention (startup.py)

Phase C — ML-Specific Attacks
  C1: Training data poisoning guard (bootstrap.py)
  C2: Normalizer plausibility bounds (normalizer.py)
  C3: Feedback multi-analyst quorum (feedback.py — partially covered)

Phase D — Operational Side-Channels
  D1: CEF log injection sanitization (alerts.py)
  D2: Dedup window burst accumulation (suppression.py)
  D3: sys.path order check (startup.py)
"""
from __future__ import annotations

import json
import math
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Phase A1 — Bootstrap Reset Lockout
# ---------------------------------------------------------------------------

class TestBootstrapResetLockout:
    """A1: MATURE -> OBSERVE re-bootstrap must be gated behind lockout + emergency flag."""

    def _make_mature_protocol(self):
        from chimera.engine.bootstrap import BootstrapConfig, BootstrapProtocol
        cfg = BootstrapConfig(
            min_observe=1,
            min_warm=2,
            stability_window=1,
            stability_ceiling=1.0,   # always stable
            reset_lockout_seconds=3600.0,
            require_emergency_flag=True,
        )
        bp = BootstrapProtocol(config=cfg)
        # Drive to MATURE quickly
        for _ in range(3):
            bp.ingest({"user_id": "alice", "timestamp": "2024-01-01T09:00:00"})
        bp.record_instability(0.01, 0.5)   # stable window
        # Now manually force MATURE
        bp._phase = "mature"
        bp._mature_since = time.time()
        return bp

    def test_rollback_without_emergency_flag_is_blocked(self):
        """Calling _transition_to('observe') without emergency=True must be a no-op."""
        bp = self._make_mature_protocol()
        bp._transition_to("observe", reason="attacker reset")
        assert bp.phase == "mature", "Phase must stay MATURE when emergency=False"

    def test_rollback_within_lockout_window_is_blocked(self):
        """emergency=True but within lockout period must still be blocked."""
        bp = self._make_mature_protocol()
        bp._mature_since = time.time()   # just entered MATURE
        bp._transition_to("observe", reason="too-fast reset", emergency=True)
        assert bp.phase == "mature", "Phase must stay MATURE within lockout window"

    def test_emergency_reset_after_lockout_is_allowed(self):
        """emergency=True after lockout has elapsed must succeed."""
        bp = self._make_mature_protocol()
        # Pretend we matured >1h ago
        bp._mature_since = time.time() - 7200.0
        bp._transition_to("observe", reason="grace period elapsed", emergency=True)
        assert bp.phase == "observe"

    def test_public_emergency_method_logs_and_transitions(self, caplog):
        """transition_to_observe_emergency() must log CRITICAL and transition (after lockout)."""
        import logging
        bp = self._make_mature_protocol()
        bp._mature_since = time.time() - 7200.0
        with caplog.at_level(logging.CRITICAL, logger="chimera.engine.bootstrap"):
            bp.transition_to_observe_emergency("SOC-authorized reset")
        assert bp.phase == "observe"
        assert any("EMERGENCY" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Phase A2 — Slow Behavioral Drift Detection (DriftGuard)
# ---------------------------------------------------------------------------

class TestDriftGuard:
    """A2: Boiling-frog slow-shift must be detected before full normalization."""

    def test_cumulative_drift_triggers_critical(self, tmp_path):
        from chimera.engine.drift_guard import DriftGuard
        guard = DriftGuard(
            baseline_path=tmp_path / "baselines.json",
            max_drift_deg_per_day=360.0,   # disable velocity threshold
            max_total_drift_deg=45.0,       # 45° total cap
            velocity_window=2,
        )

        # Establish baseline at 0° (midnight)
        alert = guard.observe("bob", math.radians(0))
        assert alert is None    # baseline set, no history yet

        # Shift by 60° (~4h) — should exceed 45° cap
        alert = guard.observe("bob", math.radians(60))
        assert alert is not None
        assert alert.severity == "CRITICAL"
        assert alert.cumulative_drift_deg >= 45.0

    def test_rapid_velocity_triggers_warning(self, tmp_path):
        from chimera.engine.drift_guard import DriftGuard
        guard = DriftGuard(
            baseline_path=tmp_path / "baselines.json",
            max_drift_deg_per_day=15.0,     # low velocity cap
            max_total_drift_deg=360.0,       # no cumulative cap
            velocity_window=2,
            measurement_interval_hours=24.0,
        )
        guard.observe("carol", math.radians(0))   # baseline
        guard.observe("carol", math.radians(0))   # 0° velocity
        # Now shift by 20° in one step — velocity = 20°/day > 15° cap
        alert = guard.observe("carol", math.radians(20))
        assert alert is not None
        assert alert.severity == "WARNING"

    def test_stable_user_no_alert(self, tmp_path):
        from chimera.engine.drift_guard import DriftGuard
        guard = DriftGuard(
            baseline_path=tmp_path / "baselines.json",
            max_drift_deg_per_day=30.0,
            max_total_drift_deg=90.0,
            velocity_window=3,
        )
        mu_rad = math.radians(180)
        guard.observe("dave", mu_rad)
        guard.observe("dave", mu_rad)
        alert = guard.observe("dave", mu_rad)    # no drift at all
        assert alert is None

    def test_baselines_persisted_across_instances(self, tmp_path):
        from chimera.engine.drift_guard import DriftGuard, _mu_to_deg
        path = tmp_path / "baselines.json"
        g1 = DriftGuard(baseline_path=path, max_drift_deg_per_day=360.0, max_total_drift_deg=360.0)
        g1.observe("eve", math.radians(90))   # sets baseline

        g2 = DriftGuard(baseline_path=path, max_drift_deg_per_day=360.0, max_total_drift_deg=360.0)
        status = g2.get_status("eve")
        assert abs(status["baseline_mu_deg"] - 90.0) < 1.0, "Baseline must survive round-trip"


# ---------------------------------------------------------------------------
# Phase A3 — Hard Score Floor Bypass (suppression.py)
# ---------------------------------------------------------------------------

class TestHardScoreFloor:
    """A3: Extreme anomaly scores must bypass the multi-signal gate entirely."""

    def test_extreme_score_always_emits_regardless_of_signals(self):
        from chimera.suppression import FPSuppressor
        sup = FPSuppressor(min_signals=3, hard_score_floor=0.97)
        # Score is 0.98 — only 1 signal would fire (insufficient for gate)
        # but hard floor must override
        emit, ev = sup.evaluate("frank", score=0.98, threshold=0.5,
                                vm_nll=0.1, jsd=0.0)
        assert emit is True
        assert ev.hard_bypass is True

    def test_below_floor_respects_gate(self):
        from chimera.suppression import FPSuppressor
        sup = FPSuppressor(min_signals=2, hard_score_floor=0.97)
        # score=0.60 — 1 signal (ensemble), no temporal or JSD → should suppress
        emit, ev = sup.evaluate("grace", score=0.60, threshold=0.55,
                                vm_nll=0.1, jsd=0.05)
        assert emit is False
        assert ev.hard_bypass is False

    def test_hard_floor_cannot_be_circumvented_by_low_score_high_jsd(self):
        """Adversary with score just below floor must still go through gate."""
        from chimera.suppression import FPSuppressor
        sup = FPSuppressor(min_signals=3, hard_score_floor=0.97, jsd_floor=0.2)
        # score=0.96 — just below floor; jsd=0.9 but only 1 of 3 required signals
        emit, ev = sup.evaluate("hank", score=0.96, threshold=0.50,
                                vm_nll=0.0, jsd=0.9)
        # ensemble_fired + jsd_fired = 2 signals < min_signals=3 → suppress
        assert emit is False


# ---------------------------------------------------------------------------
# Phase A4 — Fleet Monitor (Coordinated Attack Detection)
# ---------------------------------------------------------------------------

class TestFleetMonitor:
    """A4: Cross-user fleet-wide attacks must be flagged even when individual scores are low."""

    def test_mass_new_ip_triggers_alert(self):
        from chimera.fleet_monitor import FleetMonitor
        fm = FleetMonitor(
            window_minutes=60,
            mass_new_ip_threshold=0.30,   # 30% of users
            min_population=5,
        )
        # Register 10 users logging in from new IPs — collect ALL alerts
        all_alerts = []
        for i in range(10):
            all_alerts += fm.record_login(f"user{i}", ip=f"10.0.0.{i}", is_anomalous=False)
        # 100% new IPs >= 30% threshold; alert should fire at some point
        alert_types = [a.alert_type for a in all_alerts]
        assert "MASS_NEW_IP" in alert_types

    def test_asn_concentration_triggers_alert(self):
        from chimera.fleet_monitor import FleetMonitor
        fm = FleetMonitor(
            window_minutes=60,
            asn_concentration_threshold=0.60,
            min_population=5,
        )
        all_alerts = []
        for i in range(10):
            all_alerts += fm.record_login(f"u{i}", ip=f"1.2.3.{i}", asn="AS64512")
        alert_types = [a.alert_type for a in all_alerts]
        assert "ASN_CONCENTRATION" in alert_types

    def test_synchronized_anomaly_triggers_alert(self):
        from chimera.fleet_monitor import FleetMonitor
        fm = FleetMonitor(
            window_minutes=60,
            sync_anomaly_threshold=0.40,
            min_population=5,
        )
        all_alerts = []
        for i in range(10):
            all_alerts += fm.record_login(f"x{i}", is_anomalous=True)
        alert_types = [a.alert_type for a in all_alerts]
        assert "SYNCHRONIZED_ANOMALY" in alert_types

    def test_below_min_population_no_alerts(self):
        from chimera.fleet_monitor import FleetMonitor
        fm = FleetMonitor(min_population=20, window_minutes=60)
        alerts = []
        for i in range(5):
            alerts += fm.record_login(f"v{i}", ip=f"9.9.9.{i}", is_anomalous=True)
        assert alerts == [], "Below min_population must produce no alerts"


# ---------------------------------------------------------------------------
# Phase B3 — Import Injection Prevention (startup.py)
# ---------------------------------------------------------------------------

class TestImportInjection:
    """B3: Modules loaded from outside the chimera install prefix must be detected."""

    def test_clean_installation_passes(self):
        from chimera.engine.startup import verify_chimera_installation
        violations = verify_chimera_installation(strict=False)
        # In a clean test environment there should be no violations
        assert violations == [], f"Unexpected violations: {violations}"

    def test_injected_module_detected(self, tmp_path):
        """Simulate a shadowed module by patching its __file__ to a tmp path."""
        from chimera.engine.startup import verify_chimera_installation
        fake_path = tmp_path / "chimera" / "fake_module.py"
        fake_path.parent.mkdir(parents=True, exist_ok=True)
        fake_path.write_text("# malicious module")

        # Create a fake module objects and insert into sys.modules
        fake_mod = MagicMock()
        fake_mod.__file__ = str(fake_path)
        sys.modules["chimera._injected_test_module"] = fake_mod
        try:
            violations = verify_chimera_installation(strict=False)
            assert any("_injected_test_module" in v for v in violations), (
                "Injected module must be detected as a violation"
            )
        finally:
            del sys.modules["chimera._injected_test_module"]


# ---------------------------------------------------------------------------
# Phase C1 — Training Data Poisoning Guard
# ---------------------------------------------------------------------------

class TestTrainingDataPoisoning:
    """C1: High anomaly rate during OBSERVE must block OBSERVE -> WARM transition."""

    def test_high_anomaly_rate_blocks_transition(self):
        from chimera.engine.bootstrap import BootstrapConfig, BootstrapProtocol
        # Very fast observe (1 event), high anomaly ceiling of 5%
        cfg = BootstrapConfig(
            min_observe=5,
            observe_anomaly_ceiling=0.05,  # 5% ceiling
            observe_anomaly_ema_alpha=0.9,  # fast EMA
        )
        bp = BootstrapProtocol(config=cfg)
        # Inject 10 high-score events (all anomalous: score > 0.5)
        raw_scores = {"model_a": 0.9, "model_b": 0.85}
        for i in range(10):
            bp.ingest({"user_id": "attacker", "timestamp": "2024-01-01T02:00:00"},
                      raw_scores=raw_scores)
        # EMA should exceed 5% ceiling — transition must be blocked
        assert bp._observe_poisoning_suspected is True
        assert bp.phase == "observe", "Must stay in OBSERVE when poisoning suspected"

    def test_normal_rate_allows_transition(self):
        from chimera.engine.bootstrap import BootstrapConfig, BootstrapProtocol
        cfg = BootstrapConfig(
            min_observe=3,
            min_warm=999,   # don't transition to MATURE
            observe_anomaly_ceiling=0.50,  # 50% ceiling — very permissive
            observe_anomaly_ema_alpha=0.5,
        )
        bp = BootstrapProtocol(config=cfg)
        low_scores = {"model_a": 0.1}
        for i in range(5):
            bp.ingest({"user_id": "normal", "timestamp": "2024-01-01T09:00:00"},
                      raw_scores=low_scores)
        assert bp._observe_poisoning_suspected is False
        # Should have transitioned to WARM
        assert bp.phase == "warm"


# ---------------------------------------------------------------------------
# Phase C2 — Normalizer Plausibility Bounds
# ---------------------------------------------------------------------------

class TestNormalizerPlausibility:
    """C2: Zeroed or degenerate normalizer params must be rejected on load."""

    def _write_normalizer_json(self, path: Path, params: dict) -> None:
        data = {
            "version": "0.4",
            "strategy": "minmax",
            "low_variance_threshold": 1e-4,
            "collapse_epsilon": 1e-6,
            "quantile_range": [0.05, 0.95],
            "params": params,
        }
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_all_zero_params_rejected(self, tmp_path):
        from chimera.engine.normalizer import ScoreNormalizer
        from chimera.engine.exceptions import IntegrityError
        p = tmp_path / "norm.json"
        self._write_normalizer_json(p, {"if_model": {"lo": 0.0, "hi": 0.0}})
        with pytest.raises(IntegrityError, match="all-zero"):
            ScoreNormalizer.load(p)

    def test_degenerate_range_rejected(self, tmp_path):
        from chimera.engine.normalizer import ScoreNormalizer
        from chimera.engine.exceptions import IntegrityError
        p = tmp_path / "norm.json"
        self._write_normalizer_json(p, {"lof_model": {"lo": 0.5, "hi": 0.5,
                                                       "q_lo": 0.5, "q_hi": 0.5}})
        with pytest.raises(IntegrityError, match="degenerate"):
            ScoreNormalizer.load(p)

    def test_valid_params_loaded_successfully(self, tmp_path):
        from chimera.engine.normalizer import ScoreNormalizer
        p = tmp_path / "norm.json"
        self._write_normalizer_json(p, {"if_model": {"lo": 0.1, "hi": 0.9,
                                                      "q_lo": 0.15, "q_hi": 0.85}})
        norm = ScoreNormalizer.load(p)
        assert norm.is_fitted("if_model")


# ---------------------------------------------------------------------------
# Phase D1 — CEF Log Injection Sanitization
# ---------------------------------------------------------------------------

class TestCEFInjection:
    """D1: Adversarial usernames and field values must not split CEF syslog records."""

    def _make_alert(self, user: str = "alice", extra_event: dict = None):
        from chimera.alerts import Alert
        event = {"user_id": user, "timestamp": "2024-01-01T09:00:00"}
        if extra_event:
            event.update(extra_event)
        return Alert.from_scored_event(
            event=event,
            score=0.75,
            threshold=0.50,
            models_firing=["if"],
            signals_firing=["ensemble_score"],
            jsd=0.1,
            vm_nll=2.0,
        )

    def test_newline_in_username_produces_single_cef_line(self):
        """The primary CEF injection vector: username with embedded newline."""
        alert = self._make_alert(user="alice\nCEF:0|Evil|forge|0.0|FAKE|fake|10|")
        cef = alert.to_cef()
        # Must produce exactly ONE line (no newline splitting the record)
        assert "\n" not in cef, f"CEF record was split by newline injection: {cef!r}"

    def test_carriage_return_in_username_stripped(self):
        """CR must also be stripped to prevent CRLF-based injection."""
        alert = self._make_alert(user="alice\r\nEvil")
        cef = alert.to_cef()
        assert "\r" not in cef
        assert "\n" not in cef

    def test_crlf_in_tags_stripped(self):
        """CRLF in tags must be stripped — the CEF record must be one line."""
        from chimera.alerts import Alert
        alert = Alert.from_scored_event(
            event={"user_id": "bob"},
            score=0.8, threshold=0.5,
            models_firing=[], signals_firing=[],
            tags=["tag1\r\nFakeEvent: injected"],
        )
        cef = alert.to_cef()
        # Newlines must be gone — record must not be split
        assert "\r" not in cef, "CR must be stripped from CEF output"
        assert "\n" not in cef, "LF must be stripped from CEF output"

    def test_equals_in_ip_escaped(self):
        """Equals sign in extension values must be escaped per CEF spec."""
        alert = self._make_alert(extra_event={"ip_address": "1.2.3.4=injected"})
        cef = alert.to_cef()
        # Unescaped '=' in extension values breaks field parsing
        # After sanitization, it should appear as '\=' not '='
        assert "1.2.3.4=injected" not in cef


# ---------------------------------------------------------------------------
# Phase D2 — Dedup Window Burst Accumulation
# ---------------------------------------------------------------------------

class TestDedupBurstAccumulation:
    """D2: Events suppressed in dedup window must accumulate in BurstSummary."""

    def test_burst_summary_captures_suppressed_events(self):
        from chimera.suppression import FPSuppressor
        sup = FPSuppressor(
            min_signals=1,
            hard_score_floor=1.0,   # disable hard bypass
            jsd_floor=0.0,          # JSD always fires
            dedup_window_seconds=60.0,
            dedup_max_per_window=1,
        )
        # First event emitted
        emit1, _ = sup.evaluate("ivan", score=0.6, threshold=0.5, vm_nll=1.0, jsd=0.3)
        assert emit1 is True

        # Second event: deduped (window not expired)
        emit2, _ = sup.evaluate("ivan", score=0.7, threshold=0.5, vm_nll=1.0, jsd=0.3)
        assert emit2 is False

        # Third event: also deduped
        emit3, _ = sup.evaluate("ivan", score=0.8, threshold=0.5, vm_nll=1.0, jsd=0.3)
        assert emit3 is False

        # Flush should return a summary with 2 suppressed events
        summary = sup.flush_burst_summary("ivan")
        assert summary is not None
        assert summary.suppressed_count >= 2
        assert summary.max_score >= 0.7


# ---------------------------------------------------------------------------
# Phase C3 — Feedback Multi-Analyst Quorum
# ---------------------------------------------------------------------------

class TestFeedbackQuorum:
    """C3: Feedback must require multiple unique analyst verdicts before promotion."""

    def test_quorum_promotion(self, tmp_path):
        from chimera.feedback import FeedbackStore
        path = tmp_path / "feedback.ndjson"
        store = FeedbackStore(path, min_quorum=2)

        eid = "evt-123"
        # First analyst verdict
        done1 = store.record(eid, "fp", analyst_id="analyst_A")
        assert done1 is False
        assert store.fp_rate_for_user("alice") == 0.0

        # Second analyst verdict (same)
        done2 = store.record(eid, "fp", analyst_id="analyst_B", user="alice")
        assert done2 is True
        assert store.fp_rate_for_user("alice") == 1.0

    def test_duplicate_analyst_ignored(self, tmp_path):
        from chimera.feedback import FeedbackStore
        store = FeedbackStore(tmp_path / "f.ndjson", min_quorum=2)
        eid = "evt-456"
        store.record(eid, "fp", analyst_id="A")
        store.record(eid, "fp", analyst_id="A")  # duplicate
        assert store._is_confirmed(eid, "fp") is False

    def test_analyst_poisoning_detection(self, tmp_path, caplog):
        from chimera.feedback import FeedbackStore
        store = FeedbackStore(tmp_path / "p.ndjson", min_quorum=2)
        
        # Setup 5 events with consensus on TP
        for i in range(5):
            eid = f"e{i}"
            store.record(eid, "tp", analyst_id="B")
            store.record(eid, "tp", analyst_id="C")
            # Attacker B labels them all as FP
            store.record(eid, "fp", analyst_id="Attacker")
        
        poisoned = store.detect_analyst_poisoning()
        assert "Attacker" in poisoned


# ---------------------------------------------------------------------------
# Phase B1/B2 — Crypto Integrity (Genesis & SecureBuffer)
# ---------------------------------------------------------------------------

class TestCryptoIntegrity:
    """B1/B2: Genesis blocks and SecureBuffer key protection."""

    def test_genesis_block_creation_and_requirement(self, tmp_path):
        from chimera.crypto import EncryptedNDJSONWriter, EncryptedNDJSONReader
        key = b"1" * 32
        path = tmp_path / "secret.log"
        
        # New file should get a genesis block
        writer = EncryptedNDJSONWriter(path, key)
        writer.write({"secret": "data"})
        
        # Reader must find the genesis block
        reader = EncryptedNDJSONReader(path, key)
        records = reader.read_all(verify_chain=True)
        assert len(records) == 1
        assert records[0]["secret"] == "data"
        
        # Manual tamper: delete genesis line
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[1:]))
        with pytest.raises(ValueError, match="missing required GenesisBlock"):
            reader.read_all()

    def test_secure_buffer_wipe(self):
        from chimera.crypto import SecureBuffer
        secret = b"mysecretkey"
        with SecureBuffer(secret) as buf:
            assert buf.get() == secret
        # Outside 'with' block, memory should be zeroed
        assert all(b == 0 for b in buf._data)

    def test_no_signal_suppressions_return_no_burst(self):
        """Gate-suppressed events (0 signals) must NOT accumulate in burst log."""
        from chimera.suppression import FPSuppressor
        sup = FPSuppressor(min_signals=3, hard_score_floor=1.0)   # suppresses everything (0 signals)
        sup.evaluate("jane", score=0.1, threshold=0.5, vm_nll=0.0, jsd=0.0)
        summary = sup.flush_burst_summary("jane")
        # 0-signal gate suppression must not be counted as burst event
        assert summary is None or summary.suppressed_count == 0

"""
chimera.engine.bootstrap — Three-phase self-provisioning state machine.

Chimera requires no pre-labeled training data and no configuration beyond a
log source. This module implements the autonomous bootstrapping protocol that
takes Chimera from a cold start to full detection through three distinct phases:

    OBSERVE  → accumulate events, fit wide priors, emit no alerts
    WARM     → score events, suppress alerts, monitor stability
    MATURE   → full detection + alert emission + adversarial probe detection

The transition criteria are configurable but default to empirically reasonable
values for a medium-sized organization (~50–500 users).

Design rationale
----------------
The core challenge of self-provisioning anomaly detection is the cold-start
problem: you cannot detect anomalies until you know what "normal" looks like,
but you need to ingest events to learn normal. The three-phase protocol solves
this by decoupling ingestion (always on) from detection (phase-gated).

Phase transitions are driven by:
1. Event count thresholds (MIN_OBSERVE, MIN_WARM)
2. Stability criterion: threshold instability < STABILITY_CEILING for
   STABILITY_WINDOW consecutive scoring windows

This prevents premature maturation on noisy or attack-heavy initial traffic.
"""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

import numpy as np

from chimera.engine.online import OnlineVonMisesUpdater
from chimera.engine.exceptions import BootstrapPhaseError

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Types
# ------------------------------------------------------------------

BootstrapPhase = Literal["observe", "warm", "mature"]

# Phase transition thresholds (tunable via BootstrapConfig)
_DEFAULT_MIN_OBSERVE = 500     # events before fitting first model
_DEFAULT_MIN_WARM = 2_500      # events before considering maturation
_DEFAULT_STABILITY_CEILING = 0.05   # max allowed threshold instability
_DEFAULT_STABILITY_WINDOW = 3       # consecutive stable windows required
_DEFAULT_REFIT_EVERY = 500     # events between sliding-window refits in mature phase
_DEFAULT_PROBE_DRIFT_THRESHOLD = 0.08    # instability spike that may indicate probing
_DEFAULT_LOW_DETECTION_FLOOR = 0.01      # detection rate below which probing is suspected


@dataclass
class BootstrapConfig:
    """Tunable parameters for the self-provisioning protocol."""
    min_observe: int = _DEFAULT_MIN_OBSERVE
    min_warm: int = _DEFAULT_MIN_WARM
    stability_ceiling: float = _DEFAULT_STABILITY_CEILING
    stability_window: int = _DEFAULT_STABILITY_WINDOW
    refit_every: int = _DEFAULT_REFIT_EVERY
    probe_drift_threshold: float = _DEFAULT_PROBE_DRIFT_THRESHOLD
    low_detection_floor: float = _DEFAULT_LOW_DETECTION_FLOOR
    decay_alpha: float = 0.995
    # A1: Bootstrap reset lockout
    reset_lockout_seconds: float = 3600.0     # refuse re-OBSERVE if MATURE < 1h ago
    require_emergency_flag: bool = True        # re-OBSERVE needs explicit flag
    # C1: Training data poisoning guard
    observe_anomaly_ceiling: float = 0.15     # >15% anomaly rate in OBSERVE = suspect
    observe_anomaly_ema_alpha: float = 0.1    # EMA smoothing for anomaly rate


@dataclass
class PhaseTransitionEvent:
    """Emitted when the bootstrap protocol transitions between phases."""
    from_phase: BootstrapPhase
    to_phase: BootstrapPhase
    event_count: int
    timestamp: str
    reason: str
    users_seen: int
    instability_metric: float


@dataclass
class BootstrapStatus:
    """Current state of the self-provisioning protocol."""
    phase: BootstrapPhase
    event_count: int
    users_seen: int
    stable_window_count: int
    recent_instability: float
    recent_detection_rate: float
    probe_suspected: bool
    elapsed_seconds: float
    per_user_sample_counts: dict[str, int]


class BootstrapProtocol:
    """Self-provisioning three-phase state machine for Chimera.

    Manages the autonomous transition from cold start to full detection.
    Can be used standalone (call :meth:`ingest` for each event) or
    integrated into the streaming pipeline via :class:`StreamingBuffer`.

    Parameters
    ----------
    config:
        Tunable phase transition parameters.
    pipeline:
        Optional :class:`EnginePipeline` instance. If provided, the
        bootstrap protocol drives pipeline fits and scoring automatically.
        If None, the protocol only manages per-user von Mises models and
        phase state; external code must trigger pipeline fits.
    """

    def __init__(
        self,
        config: Optional[BootstrapConfig] = None,
        pipeline=None,  # Optional[EnginePipeline] — avoid circular import
    ) -> None:
        self.config = config or BootstrapConfig()
        self.pipeline = pipeline

        # Phase state
        self._phase: BootstrapPhase = "observe"
        self._event_count: int = 0
        self._phase_start_time: float = time.monotonic()
        self._start_time: float = time.monotonic()
        self._mature_since: Optional[float] = None   # wall time when MATURE entered

        # Per-user incremental von Mises tracking (always running)
        self._vm_updater = OnlineVonMisesUpdater(decay_alpha=self.config.decay_alpha)

        # Stability monitoring (warm + mature phases)
        self._instability_history: deque[float] = deque(maxlen=50)
        self._stable_window_count: int = 0
        self._recent_detection_rate: float = 0.0
        self._probe_suspected: bool = False

        # Event accumulation for batch fits (observe → warm transition)
        self._observe_buffer: list[dict] = []

        # C1: Training data poisoning guard
        self._observe_anomaly_ema: float = 0.0
        self._observe_poisoning_suspected: bool = False

        # Transition log
        self._transitions: list[PhaseTransitionEvent] = []

        logger.info("[bootstrap] Initialized in OBSERVE phase.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def phase(self) -> BootstrapPhase:
        """Current bootstrap phase."""
        return self._phase

    @property
    def event_count(self) -> int:
        """Total events ingested since initialization."""
        return self._event_count

    def ingest(self, event: dict, raw_scores: Optional[dict[str, float]] = None) -> Optional[dict]:
        """Process one event through the bootstrap protocol.

        Parameters
        ----------
        event:
            Authentication event dict. Must contain ``user_id`` (or
            ``username``) and ``timestamp`` (or ``event_time``) fields.
        raw_scores:
            Optional dict of ``model_id → float`` raw anomaly scores for
            this event. Required for scoring in warm/mature phases.

        Returns
        -------
        dict or None
            In OBSERVE and WARM phases: always None (no alerts emitted).
            In MATURE phase: an alert dict if anomalous, else None.
        """
        self._event_count += 1

        # Always update per-user von Mises model (O(1))
        user = event.get("user_id") or event.get("username", "unknown")
        ts = event.get("timestamp") or event.get("event_time")
        hour = self._extract_hour(ts)
        if hour is not None:
            self._vm_updater.update(user, hour)

        # Buffer events during observe phase for batch fit
        if self._phase == "observe":
            self._observe_buffer.append(event)
            self._check_observe_data_poisoning(raw_scores)
            self._check_observe_transition()
            return None

        elif self._phase == "warm":
            self._check_warm_transition(raw_scores)
            return None  # suppress all alerts during warm-up

        else:  # mature
            return self._mature_ingest(event, raw_scores)

    def get_vm_model(self, user: str):
        """Return the current von Mises model for a user."""
        return self._vm_updater.get_model(user)

    def status(self) -> BootstrapStatus:
        """Return the current protocol status."""
        return BootstrapStatus(
            phase=self._phase,
            event_count=self._event_count,
            users_seen=len(self._vm_updater.all_users()),
            stable_window_count=self._stable_window_count,
            recent_instability=float(np.mean(list(self._instability_history)))
            if self._instability_history else 0.0,
            recent_detection_rate=self._recent_detection_rate,
            probe_suspected=self._probe_suspected,
            elapsed_seconds=time.monotonic() - self._start_time,
            per_user_sample_counts={
                u: int(self._vm_updater.get_effective_n(u))
                for u in self._vm_updater.all_users()
            },
        )

    def record_instability(self, instability: float, detection_rate: float) -> None:
        """Called by pipeline after a refit window to update stability metrics.

        Parameters
        ----------
        instability:
            Threshold instability metric from DynamicThreshold (0 = stable).
        detection_rate:
            Fraction of events in the last window that triggered detections.
        """
        self._instability_history.append(instability)
        self._recent_detection_rate = detection_rate
        self._check_probe_pattern(instability, detection_rate)

        if self._phase == "warm":
            self._check_warm_transition()

    def to_state_dict(self) -> dict:
        """Serialize protocol state (for pipeline persistence)."""
        return {
            "phase": self._phase,
            "event_count": self._event_count,
            "stable_window_count": self._stable_window_count,
            "recent_detection_rate": self._recent_detection_rate,
            "instability_history": list(self._instability_history),
            "probe_suspected": self._probe_suspected,
            "vm_updater": self._vm_updater.to_state_dict(),
            "config": {
                "min_observe": self.config.min_observe,
                "min_warm": self.config.min_warm,
                "stability_ceiling": self.config.stability_ceiling,
                "stability_window": self.config.stability_window,
                "refit_every": self.config.refit_every,
                "probe_drift_threshold": self.config.probe_drift_threshold,
                "low_detection_floor": self.config.low_detection_floor,
                "decay_alpha": self.config.decay_alpha,
            },
            "transitions": [
                {
                    "from_phase": t.from_phase,
                    "to_phase": t.to_phase,
                    "event_count": t.event_count,
                    "timestamp": t.timestamp,
                    "reason": t.reason,
                    "users_seen": t.users_seen,
                    "instability_metric": t.instability_metric,
                }
                for t in self._transitions
            ],
        }

    def save(self, path: str | Path) -> None:
        """Save protocol state to JSON (Twin Sync redundancy)."""
        from chimera.engine.safe_io import atomic_sync_write_text
        atomic_sync_write_text(
            path, json.dumps(self.to_state_dict(), indent=2), mode=0o600
        )
        logger.debug("[bootstrap] Saved state to %s (and .bak mirror)", path)

    @classmethod
    def load(cls, path: str | Path, pipeline=None) -> "BootstrapProtocol":
        """Load a saved protocol state with automatic redundancy fallback."""
        from chimera.engine.safe_io import load_with_fallback
        path = Path(path)
        bak_path = path.with_suffix(path.suffix + ".bak")
        
        # A1: Load with redundancy mirror fallback
        # First, try to load primary directly to detect content errors (corruption)
        try:
            if not path.exists():
                raise FileNotFoundError()
            bytes_data = path.read_bytes()
            data = json.loads(bytes_data.decode("utf-8"))
        except (Exception, FileNotFoundError) as e:
            if bak_path.exists():
                logger.critical(
                    "[bootstrap] PRIMARY STATE CORRUPT or missing (%s): %s. "
                    "Engaging FAIL-SAFE REDUNDANCY: loading from backup.",
                    type(e).__name__, path.name
                )
                bytes_data = load_with_fallback(path, force_backup=True)
                data = json.loads(bytes_data.decode("utf-8"))
            else:
                raise
        
        config_data = data.get("config", {})
        config = BootstrapConfig(**config_data)
        inst = cls(config=config, pipeline=pipeline)
        inst._phase = data["phase"]
        inst._event_count = data["event_count"]
        inst._stable_window_count = data["stable_window_count"]
        inst._recent_detection_rate = data["recent_detection_rate"]
        inst._instability_history = deque(
            data.get("instability_history", []), maxlen=50
        )
        inst._probe_suspected = data.get("probe_suspected", False)
        inst._vm_updater = OnlineVonMisesUpdater.from_state_dict(data["vm_updater"])
        return inst

    # ------------------------------------------------------------------
    # Phase transition logic
    # ------------------------------------------------------------------

    def _check_observe_transition(self) -> None:
        if self._event_count >= self.config.min_observe:
            if self._observe_poisoning_suspected:
                logger.warning(
                    "[bootstrap] OBSERVE -> WARM transition BLOCKED: "
                    "training data poisoning currently suspected "
                    "(anomaly_ema=%.2f%% > ceiling=%.2f%%). "
                    "Awaiting anomaly rate to normalize.",
                    self._observe_anomaly_ema * 100,
                    self.config.observe_anomaly_ceiling * 100,
                )
                return
            self._transition_to("warm", reason=f"observe threshold reached ({self._event_count} events)")

    def _check_warm_transition(self, raw_scores: Optional[dict] = None) -> None:
        if self._event_count < self.config.min_warm:
            return

        # Check stability criterion
        if len(self._instability_history) < self.config.stability_window:
            return

        recent = list(self._instability_history)[-self.config.stability_window:]
        if all(v < self.config.stability_ceiling for v in recent):
            self._stable_window_count += 1
            if self._stable_window_count >= self.config.stability_window:
                self._transition_to(
                    "mature",
                    reason=(
                        f"stability criterion met: {self.config.stability_window} "
                        f"consecutive windows below instability ceiling "
                        f"({self.config.stability_ceiling:.3f})"
                    ),
                )
        else:
            # Reset stable window count on any instability spike
            self._stable_window_count = 0

    def _transition_to(
        self,
        new_phase: BootstrapPhase,
        reason: str,
        emergency: bool = False,
    ) -> None:
        from datetime import datetime, timezone
        old_phase = self._phase

        # A1: Block MATURE -> OBSERVE rollback unless emergency flag + lockout passed
        if old_phase == "mature" and new_phase == "observe":
            if self.config.require_emergency_flag and not emergency:
                logger.critical(
                    "[bootstrap] BLOCKED: attempt to roll back from MATURE to OBSERVE "
                    "without emergency=True. Possible adversarial reset attempt. "
                    "Use transition_to_observe_emergency() to override.",
                )
                return

            if self._mature_since is not None:
                age = time.time() - self._mature_since
                if age < self.config.reset_lockout_seconds:
                    logger.critical(
                        "[bootstrap] BLOCKED: MATURE->OBSERVE reset after only %.0fs "
                        "(lockout=%.0fs). Possible adversarial re-bootstrap. "
                        "State WILL NOT reset.",
                        age, self.config.reset_lockout_seconds,
                    )
                    return

        self._phase = new_phase

        # Track when MATURE phase was entered (for lockout)
        if new_phase == "mature":
            self._mature_since = time.time()

        event = PhaseTransitionEvent(
            from_phase=old_phase,
            to_phase=new_phase,
            event_count=self._event_count,
            timestamp=datetime.now(timezone.utc).isoformat(),
            reason=reason,
            users_seen=len(self._vm_updater.all_users()),
            instability_metric=float(np.mean(list(self._instability_history)))
            if self._instability_history else 0.0,
        )
        self._transitions.append(event)

        logger.info(
            "[bootstrap] Phase transition: %s -> %s at event %d. Reason: %s",
            old_phase, new_phase, self._event_count, reason,
        )

        if old_phase == "observe":
            self._observe_buffer.clear()

    def transition_to_observe_emergency(self, reason: str) -> None:
        """Operator-initiated emergency reset to OBSERVE phase (A1 escape hatch).

        Requires explicit call — automated code cannot accidentally call this.
        Audit-logged at CRITICAL level.
        """
        logger.critical(
            "[bootstrap] EMERGENCY RESET to OBSERVE authorized. Reason: %s. "
            "This creates a detection gap. Ensure operator authorization.",
            reason,
        )
        self._transition_to("observe", reason=f"EMERGENCY: {reason}", emergency=True)

    def _mature_ingest(
        self, event: dict, raw_scores: Optional[dict[str, float]]
    ) -> Optional[dict]:
        """Process one event in the MATURE phase."""
        if raw_scores is None:
            return None  # cannot score without model scores

        # Periodic refit
        if self._event_count % self.config.refit_every == 0:
            logger.debug("[bootstrap] Mature phase refit at event %d", self._event_count)
            # Signal to external pipeline to recalculate threshold
            # (actual refit is orchestrated by pipeline.score with update_threshold=True)

        return None  # Alert generation delegated to FPSuppressor in pipeline

    # ------------------------------------------------------------------
    # Adversarial probe detection
    # ------------------------------------------------------------------

    def _check_probe_pattern(self, instability: float, detection_rate: float) -> None:
        """Detect if threshold is being probed by an adversary.

        A threshold probing pattern: threshold drift is HIGH (τ is shifting),
        but the detection rate is LOW (nothing is being caught above the new τ).
        This is the signature of an adversary who has observed the score
        distribution and is deliberately staying just below the threshold.
        """
        if self._phase != "mature":
            return

        if (instability > self.config.probe_drift_threshold
                and detection_rate < self.config.low_detection_floor):
            if not self._probe_suspected:
                self._probe_suspected = True
                logger.warning(
                    "[bootstrap] ⚠ THRESHOLD PROBING SUSPECTED: "
                    "instability=%.3f > threshold=%.3f, "
                    "detection_rate=%.4f < floor=%.4f. "
                    "An adversary may be learning the detection boundary.",
                    instability, self.config.probe_drift_threshold,
                    detection_rate, self.config.low_detection_floor,
                )
        else:
            self._probe_suspected = False

    def _check_observe_data_poisoning(self, raw_scores: Optional[dict]) -> None:
        """C1: Guard against training data poisoning during OBSERVE phase.

        If an adversary operates mainly during OBSERVE, their high-anomaly
        events become part of the 'normal' distribution, raising thresholds.
        We track the EMA of how often events look anomalous and alert when
        the rate exceeds the configured ceiling.
        """
        if raw_scores is None:
            return
        mean_score = sum(raw_scores.values()) / max(len(raw_scores), 1)
        is_anomalous = mean_score > 0.5   # raw IsolationForest scores center ~0.5

        alpha = self.config.observe_anomaly_ema_alpha
        self._observe_anomaly_ema = (
            alpha * float(is_anomalous) + (1.0 - alpha) * self._observe_anomaly_ema
        )

        if self._observe_anomaly_ema > self.config.observe_anomaly_ceiling:
            if not self._observe_poisoning_suspected:
                self._observe_poisoning_suspected = True
                logger.critical(
                    "[bootstrap] TRAINING DATA POISONING SUSPECTED during OBSERVE: "
                    "rolling anomaly rate=%.2f%% > ceiling=%.2f%%. "
                    "Attacker may be injecting high-anomaly events to corrupt the baseline. "
                    "OBSERVE -> WARM transition will be blocked until rate normalizes.",
                    self._observe_anomaly_ema * 100,
                    self.config.observe_anomaly_ceiling * 100,
                )
        else:
            if self._observe_poisoning_suspected:
                logger.info(
                    "[bootstrap] Anomaly rate normalized (%.2f%%). "
                    "Poisoning suspicion cleared.",
                    self._observe_anomaly_ema * 100,
                )
            self._observe_poisoning_suspected = False

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_hour(ts) -> Optional[float]:
        """Extract hour-of-day (float, [0,24)) from a timestamp value."""
        if ts is None:
            return None
        try:
            if hasattr(ts, "hour"):
                return float(ts.hour) + float(ts.minute) / 60.0
            if isinstance(ts, (int, float)):
                import datetime
                return float(datetime.datetime.fromtimestamp(ts).hour)
            if isinstance(ts, str):
                import datetime
                dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt.hour + dt.minute / 60.0
        except (ValueError, AttributeError, TypeError, OSError):
            pass
        return None

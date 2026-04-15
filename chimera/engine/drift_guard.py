"""
chimera.engine.drift_guard — Adversarial behavioral drift detection (v0.4.2).

Defends against the "Boiling Frog" attack: an adversary who slowly shifts
their login time by a few minutes per day, staying within the online von
Mises updater's decay window, until their 3 AM logins are fully "normalized."

How it works
------------
After each MATURE-phase event, the DriftGuard:

1. Computes the ANGULAR VELOCITY of each user's von Mises mean (μ) over a
   rolling window. If velocity > max_drift_deg_per_day → WARNING.

2. Compares the CURRENT μ to the INITIAL MATURE BASELINE μ stored when the
   user first reached the MATURE phase. If the cumulative angular distance
   exceeds max_total_drift_deg → CRITICAL alert.

Both alert thresholds are tunable. Baselines are persisted to a
JSON file that is registered with IntegrityManifest
— resetting this file is itself a detectable attack.

Design notes
------------
- Angular distance uses the circular/von Mises geodesic (not Euclidean),
  so 23:30 → 00:30 is correctly computed as 60°, not 23h worth.
- All μ values are stored in degrees [0, 360) for readability.
- Baselines are write-once per user (only updated when a user first matures).
"""
from __future__ import annotations

import json
import logging
import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Default thresholds
_DEFAULT_MAX_DRIFT_DEG_PER_DAY = 30.0    # > 30°/day = 2 hour/day shift → suspicious
_DEFAULT_MAX_TOTAL_DRIFT_DEG = 90.0      # > 90° total from baseline → critical
_DEFAULT_VELOCITY_WINDOW = 7             # rolling window in units of "measurements"
_HOURS_TO_DEG = 15.0                     # 360° / 24h


def _angular_distance(a_deg: float, b_deg: float) -> float:
    """Shortest arc between two angles on the circle, in degrees [0, 180]."""
    diff = abs(a_deg - b_deg) % 360.0
    return min(diff, 360.0 - diff)


def _rad_to_deg(r: float) -> float:
    return math.degrees(r) % 360.0


def _mu_to_deg(mu_rad: float) -> float:
    """Convert von Mises μ (radians, [-π, π]) to degrees [0, 360)."""
    return math.degrees(mu_rad) % 360.0


@dataclass
class DriftAlert:
    """Emitted when a user's behavioral shift exceeds safe thresholds."""
    user: str
    drift_velocity_deg_per_day: float      # rate of current shift
    cumulative_drift_deg: float            # total from initial baseline
    initial_mu_deg: float                  # baseline μ at MATURE entry
    current_mu_deg: float                  # most recent μ estimate
    severity: str                          # "WARNING" | "CRITICAL"
    timestamp: str


class DriftGuard:
    """Per-user circular drift velocity monitor.

    Parameters
    ----------
    baseline_path:
        Path to JSON file for persisting initial MATURE baselines.
        Will be created on first use. Should be registered with an
        IntegrityManifest by the caller.
    max_drift_deg_per_day:
        Angular velocity threshold. Shifts faster than this per day
        trigger a WARNING.
    max_total_drift_deg:
        Maximum cumulative angular distance from the initial MATURE
        baseline before a CRITICAL alert is emitted.
    velocity_window:
        Number of recent observations to use for velocity estimation.
    measurement_interval_hours:
        Assumed time between observations (used to convert window
        measurements to a per-day velocity). Default 24 = one observation
        per day; for streaming systems, reduce to e.g. 1.
    """

    def __init__(
        self,
        baseline_path: str | Path,
        max_drift_deg_per_day: float = _DEFAULT_MAX_DRIFT_DEG_PER_DAY,
        max_total_drift_deg: float = _DEFAULT_MAX_TOTAL_DRIFT_DEG,
        velocity_window: int = _DEFAULT_VELOCITY_WINDOW,
        measurement_interval_hours: float = 1.0,
    ) -> None:
        self.baseline_path = Path(baseline_path)
        self.max_drift_deg_per_day = max_drift_deg_per_day
        self.max_total_drift_deg = max_total_drift_deg
        self.velocity_window = velocity_window
        self.measurement_interval_hours = measurement_interval_hours

        # Persistent initial baselines (write-once per user)
        self._baselines: dict[str, float] = {}   # user → μ_deg at MATURE entry

        # Rolling μ history per user for velocity estimation
        self._mu_history: dict[str, deque[float]] = {}

        self._load_baselines()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, user: str, mu_rad: float) -> Optional[DriftAlert]:
        """Record a new μ observation for a user and check for drift.

        Parameters
        ----------
        user:
            User identifier.
        mu_rad:
            Current von Mises μ estimate in radians (from OnlineVonMisesUpdater).

        Returns
        -------
        DriftAlert if a threshold is exceeded, otherwise None.
        """
        mu_deg = _mu_to_deg(mu_rad)

        # Record baseline on first observation (MATURE entry point)
        if user not in self._baselines:
            self._baselines[user] = mu_deg
            self._save_baselines()
            logger.debug("[drift_guard] Baseline set for user %r: μ=%.1f°", user, mu_deg)

        # Update rolling μ history
        if user not in self._mu_history:
            self._mu_history[user] = deque(maxlen=self.velocity_window)
        self._mu_history[user].append(mu_deg)

        # Need at least 2 observations for velocity
        history = list(self._mu_history[user])
        if len(history) < 2:
            return None

        # Velocity: average angular change per observation, converted to per-day
        angular_deltas = [
            _angular_distance(history[i], history[i - 1])
            for i in range(1, len(history))
        ]
        avg_delta_per_obs = sum(angular_deltas) / len(angular_deltas)
        velocity_deg_per_day = avg_delta_per_obs * (24.0 / max(self.measurement_interval_hours, 0.1))

        # Cumulative drift from initial baseline
        baseline = self._baselines[user]
        cumulative_drift = _angular_distance(baseline, mu_deg)

        alert = self._check_thresholds(user, velocity_deg_per_day, cumulative_drift, baseline, mu_deg)
        return alert

    def reset_baseline(self, user: str, new_mu_rad: float, reason: str = "") -> None:
        """Manually reset a user's baseline (requires explicit operator action).

        The reset is logged at CRITICAL level with the reason. This is an
        intentional escape hatch for legitimate schedule changes (e.g. user
        switches to night shift) but must always leave an audit trail.
        """
        new_deg = _mu_to_deg(new_mu_rad)
        old_deg = self._baselines.get(user, None)
        self._baselines[user] = new_deg
        self._mu_history.pop(user, None)
        self._save_baselines()
        logger.critical(
            "[drift_guard] BASELINE RESET for user %r: %.1f° → %.1f°. Reason: %s",
            user, old_deg or 0.0, new_deg, reason or "(no reason given)",
        )

    def get_status(self, user: str) -> dict:
        """Return current drift statistics for a user."""
        if user not in self._baselines:
            return {"user": user, "status": "no_baseline"}

        history = list(self._mu_history.get(user, []))
        current_mu = history[-1] if history else None
        baseline = self._baselines[user]
        cumulative = _angular_distance(baseline, current_mu) if current_mu is not None else 0.0

        return {
            "user": user,
            "baseline_mu_deg": baseline,
            "current_mu_deg": current_mu,
            "cumulative_drift_deg": cumulative,
            "history_length": len(history),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_thresholds(
        self,
        user: str,
        velocity: float,
        cumulative: float,
        baseline: float,
        current: float,
    ) -> Optional[DriftAlert]:
        now = datetime.now(timezone.utc).isoformat()

        if cumulative >= self.max_total_drift_deg:
            logger.critical(
                "[drift_guard] ⛔ CRITICAL DRIFT for user %r: cumulative=%.1f° ≥ limit=%.1f°. "
                "Baseline=%.1f°, current=%.1f°. "
                "Possible adversarial normalization of malicious login time.",
                user, cumulative, self.max_total_drift_deg, baseline, current,
            )
            return DriftAlert(
                user=user,
                drift_velocity_deg_per_day=velocity,
                cumulative_drift_deg=cumulative,
                initial_mu_deg=baseline,
                current_mu_deg=current,
                severity="CRITICAL",
                timestamp=now,
            )

        if velocity >= self.max_drift_deg_per_day:
            logger.warning(
                "[drift_guard] ⚠ RAPID DRIFT for user %r: velocity=%.1f°/day ≥ limit=%.1f°/day. "
                "Baseline=%.1f°, current=%.1f°.",
                user, velocity, self.max_drift_deg_per_day, baseline, current,
            )
            return DriftAlert(
                user=user,
                drift_velocity_deg_per_day=velocity,
                cumulative_drift_deg=cumulative,
                initial_mu_deg=baseline,
                current_mu_deg=current,
                severity="WARNING",
                timestamp=now,
            )

        return None

    def _load_baselines(self) -> None:
        if self.baseline_path.exists():
            try:
                self._baselines = json.loads(
                    self.baseline_path.read_text(encoding="utf-8")
                )
                logger.debug(
                    "[drift_guard] Loaded %d baselines from %s",
                    len(self._baselines), self.baseline_path,
                )
            except (json.JSONDecodeError, OSError) as e:
                logger.error("[drift_guard] Failed to load baselines: %s", e)

    def _save_baselines(self) -> None:
        from chimera.engine.safe_io import atomic_write_text
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.baseline_path, json.dumps(self._baselines, indent=2), mode=0o640)

"""
chimera.engine.online — Incremental Bayesian von Mises updater.

Provides O(1)-per-event online updates to per-user von Mises (μ, κ) models
using the circular sufficient statistics (C, S, n) — the sum of cos(θ) and
sin(θ) over all observed login angles.

This allows the behavioral baseline to track legitimate behavioral drift
(e.g., a user switching to night shifts) without full batch refits, while
exponential decay ensures old observations lose influence over time.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from chimera.engine.temporal import (
    VonMisesModel,
    _TWO_PI,
    _KAPPA_MAX,
    _estimate_kappa_nr,
    _MIN_VM_SAMPLES,
)

logger = logging.getLogger(__name__)


@dataclass
class CircularSufficientStats:
    """Sufficient statistics for online von Mises parameter estimation.

    Stores the weighted sums of cos(θ) and sin(θ) over all observed
    login hours, plus effective sample count n (may be fractional due
    to exponential decay).

    From these three numbers, (μ, κ) can be reconstructed in O(1).
    """
    C: float = 0.0   # Σ w_i * cos(θ_i)
    S: float = 0.0   # Σ w_i * sin(θ_i)
    n: float = 0.0   # Σ w_i (effective sample count)

    def to_von_mises(self) -> Optional[VonMisesModel]:
        """Reconstruct (μ, κ) from sufficient statistics.

        Returns None if n < _MIN_VM_SAMPLES (insufficient data).
        """
        if self.n < _MIN_VM_SAMPLES:
            return None
        C_bar = self.C / self.n
        S_bar = self.S / self.n
        mu = float(math.atan2(S_bar, C_bar) % _TWO_PI)
        R_bar = min(float(math.sqrt(C_bar**2 + S_bar**2)), 1.0 - 1e-9)
        kappa = _estimate_kappa_nr(R_bar)
        return VonMisesModel(mu=mu, kappa=kappa, n_samples=int(self.n))


class OnlineVonMisesUpdater:
    """Per-user incremental Bayesian von Mises updater.

    Maintains circular sufficient statistics for each user and exposes
    the current best-estimate VonMisesModel. Each new login updates the
    statistics in O(1). Exponential decay simulates a sliding window,
    preventing the baseline from freezing on stale behavior patterns.

    Parameters
    ----------
    decay_alpha:
        Exponential decay factor applied to historical statistics on each
        update. ``alpha=1.0`` → no decay (all history equally weighted).
        ``alpha=0.99`` → an observation from 100 events ago contributes
        ``0.99^100 ≈ 0.37`` of its original weight. This models the
        "forgetting" of old behavior as the user's routine changes.
    min_samples_for_model:
        Minimum effective sample count before a non-flat model is returned.
    """

    def __init__(
        self,
        decay_alpha: float = 0.995,
        min_samples_for_model: int = _MIN_VM_SAMPLES,
    ) -> None:
        if not 0.0 < decay_alpha <= 1.0:
            raise ValueError(f"decay_alpha must be in (0, 1]; got {decay_alpha}")
        self.decay_alpha = decay_alpha
        self.min_samples = min_samples_for_model
        self._stats: dict[str, CircularSufficientStats] = {}

    def update(self, user: str, hour: float) -> VonMisesModel:
        """Record a new login event and return the updated model.

        Parameters
        ----------
        user:
            User identifier string.
        hour:
            Login hour in [0, 24).

        Returns
        -------
        VonMisesModel
            Current best-estimate model for this user. Returns flat prior
            (κ=0) if insufficient data.
        """
        theta = (_TWO_PI * hour) / 24.0
        cos_t = math.cos(theta)
        sin_t = math.sin(theta)

        if user not in self._stats:
            self._stats[user] = CircularSufficientStats()

        stats = self._stats[user]

        # Apply exponential decay to existing observations
        stats.C *= self.decay_alpha
        stats.S *= self.decay_alpha
        stats.n *= self.decay_alpha

        # Accumulate new observation (weight = 1.0)
        stats.C += cos_t
        stats.S += sin_t
        stats.n += 1.0

        model = stats.to_von_mises()
        if model is None:
            return VonMisesModel(mu=0.0, kappa=0.0, n_samples=int(stats.n))
        return model

    def get_model(self, user: str) -> VonMisesModel:
        """Return the current von Mises model for a user, or flat prior."""
        stats = self._stats.get(user)
        if stats is None:
            return VonMisesModel(mu=0.0, kappa=0.0, n_samples=0)
        model = stats.to_von_mises()
        return model if model is not None else VonMisesModel(mu=0.0, kappa=0.0, n_samples=int(stats.n))

    def get_effective_n(self, user: str) -> float:
        """Return the effective (decay-weighted) sample count for a user."""
        stats = self._stats.get(user)
        return stats.n if stats is not None else 0.0

    def all_users(self) -> list[str]:
        """Return list of all users with at least one recorded login."""
        return list(self._stats.keys())

    def reset_user(self, user: str) -> None:
        """Wipe a user's statistics (e.g., after an account ownership change)."""
        self._stats.pop(user, None)

    def to_state_dict(self) -> dict:
        """Serialize to a JSON-serializable dict (for pipeline persistence)."""
        return {
            "decay_alpha": self.decay_alpha,
            "min_samples": self.min_samples,
            "stats": {
                user: {"C": s.C, "S": s.S, "n": s.n}
                for user, s in self._stats.items()
            },
        }

    @classmethod
    def from_state_dict(cls, data: dict) -> "OnlineVonMisesUpdater":
        """Reconstruct from a state dict produced by :meth:`to_state_dict`."""
        inst = cls(
            decay_alpha=data["decay_alpha"],
            min_samples_for_model=data["min_samples"],
        )
        for user, s in data.get("stats", {}).items():
            inst._stats[user] = CircularSufficientStats(
                C=s["C"], S=s["S"], n=s["n"]
            )
        return inst

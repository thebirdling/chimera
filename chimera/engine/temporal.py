"""
chimera.engine.temporal — Fourier cyclic feature encoding and von Mises behavioral modeling.

Implements the "Antikythera Temporal Vectoring" protocol in concrete engineering terms:

1. **Fourier Cyclic Encoding**
   Maps hour-of-day and day-of-week onto the unit circle using sine/cosine
   projections. This preserves circular distance — 23:00 is "close" to 00:00,
   not 23 units away from it. Linear (z-score) time features make this error.

       hour_sin = sin(2π × hour / 24)
       hour_cos = cos(2π × hour / 24)
       dow_sin  = sin(2π × day_of_week / 7)
       dow_cos  = cos(2π × day_of_week / 7)

2. **von Mises Distribution Baseline**
   The von Mises distribution is the circular analog of the Gaussian, defined
   on [0, 2π]. It is the natural distribution for modeling the hour-of-login
   patterns for a specific user.

   During baselining (fit), we estimate the von Mises parameters (μ, κ) for
   each user from their historical login hours. At inference time, the negative
   log-likelihood of a new login under the user's von Mises model serves as
   a prior anomaly weight — a login at an unusual point on the 24-hour circle
   gets a higher prior anomaly score before any ML model sees it.

   For users with insufficient history (cold start), a flat (uniform) prior
   is used (κ = 0, no concentration).

Mathematical background
-----------------------
The von Mises PDF: p(θ; μ, κ) = exp(κ·cos(θ - μ)) / (2π·I₀(κ))
where I₀ is the modified Bessel function of the first kind, order 0.

The MLE for μ is the mean direction of circular observations.
The MLE for κ is estimated by solving:
    A(κ) = R̄ = 1/n |Σ exp(iθ_j)|
where A(κ) = I₁(κ)/I₀(κ) is the ratio of Bessel functions.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Minimum events to fit a von Mises model; below this, use flat prior
_MIN_VM_SAMPLES = 10
_TWO_PI = 2.0 * math.pi
_LOG_TWO_PI = math.log(_TWO_PI)

# Maximum kappa: beyond this, the user is "perfectly regular" w.r.t. login hours.
# Capping prevents numerical overflow and unbounded NLL values for near-deterministic users.
_KAPPA_MAX = 200.0

# ------------------------------------------------------------------
# Fourier cyclic encoding
# ------------------------------------------------------------------

def encode_hour_cyclic(hours: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Map hour-of-day [0, 23] to (sin, cos) on the unit circle.

    Parameters
    ----------
    hours:
        1-D array of integer or float hour values in [0, 24).

    Returns
    -------
    tuple[np.ndarray, np.ndarray]
        (hour_sin, hour_cos) arrays, values in [-1, 1].
    """
    theta = (_TWO_PI * np.asarray(hours, dtype=np.float64)) / 24.0
    return np.sin(theta), np.cos(theta)


def encode_dow_cyclic(days: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Map day-of-week [0=Mon, 6=Sun] to (sin, cos) on the unit circle.

    Parameters
    ----------
    days:
        1-D array of integer day values in [0, 6].

    Returns
    -------
    tuple[np.ndarray, np.ndarray]
        (dow_sin, dow_cos) arrays, values in [-1, 1].
    """
    theta = (_TWO_PI * np.asarray(days, dtype=np.float64)) / 7.0
    return np.sin(theta), np.cos(theta)


def encode_month_cyclic(months: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Map month [1, 12] to (sin, cos) on the unit circle."""
    theta = (_TWO_PI * (np.asarray(months, dtype=np.float64) - 1.0)) / 12.0
    return np.sin(theta), np.cos(theta)


def add_cyclic_features(df: "pd.DataFrame", timestamp_col: str = "timestamp") -> "pd.DataFrame":
    """Add Fourier cyclic time features to a DataFrame in-place.

    Adds columns: hour_sin, hour_cos, dow_sin, dow_cos, month_sin, month_cos.

    Parameters
    ----------
    df:
        DataFrame containing authentication events.
    timestamp_col:
        Name of the timestamp column (datetime-like).

    Returns
    -------
    pd.DataFrame
        DataFrame with added cyclic columns.
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas required for add_cyclic_features.")

    ts = pd.to_datetime(df[timestamp_col], errors="coerce", utc=True)

    hours = ts.dt.hour.fillna(0).values
    dows = ts.dt.dayofweek.fillna(0).values
    months = ts.dt.month.fillna(1).values

    df["hour_sin"], df["hour_cos"] = encode_hour_cyclic(hours)
    df["dow_sin"], df["dow_cos"] = encode_dow_cyclic(dows)
    df["month_sin"], df["month_cos"] = encode_month_cyclic(months)

    return df


# ------------------------------------------------------------------
# von Mises distribution
# ------------------------------------------------------------------

@dataclass
class VonMisesModel:
    """Per-user von Mises distribution parameter estimates.

    Attributes
    ----------
    mu:
        Mean direction in radians [0, 2π). The "typical login hour" in circular space.
    kappa:
        Concentration parameter κ ≥ 0.
        κ = 0: flat (uniform) prior — all hours equally likely (cold start).
        Large κ: tightly concentrated around μ (very consistent login time).
    n_samples:
        Number of events used to estimate the parameters.
    """
    mu: float = 0.0
    kappa: float = 0.0
    n_samples: int = 0


def fit_von_mises(hours: np.ndarray) -> VonMisesModel:
    """Fit von Mises parameters (μ, κ) from hour-of-login observations.

    Parameters
    ----------
    hours:
        1-D array of login hours in [0, 24).

    Returns
    -------
    VonMisesModel
        Fitted parameters. If n < _MIN_VM_SAMPLES, returns flat prior (κ=0).
    """
    hours = np.asarray(hours, dtype=np.float64)
    n = len(hours)

    if n < _MIN_VM_SAMPLES:
        return VonMisesModel(mu=0.0, kappa=0.0, n_samples=n)

    # Convert hours to angles on [0, 2π)
    theta = (_TWO_PI * hours) / 24.0

    # MLE for μ: mean direction
    sin_mean = np.sin(theta).mean()
    cos_mean = np.cos(theta).mean()
    mu = float(math.atan2(sin_mean, cos_mean) % _TWO_PI)

    # R̄: mean resultant length (circular concentration)
    R_bar = float(math.sqrt(sin_mean ** 2 + cos_mean ** 2))
    R_bar = min(R_bar, 1.0 - 1e-9)  # clamp for numerical stability

    # MLE for κ: Newton-Raphson inversion of A(κ) = R̄ (smooth, no discontinuity)
    kappa = _estimate_kappa_nr(R_bar)

    logger.debug(
        "[von_mises] fit: n=%d, mu=%.3fh (angle=%.3f rad), kappa=%.3f, R_bar=%.3f",
        n, (mu / _TWO_PI) * 24.0, mu, kappa, R_bar,
    )
    return VonMisesModel(mu=mu, kappa=kappa, n_samples=n)


def von_mises_nll(hour: float, model: VonMisesModel) -> float:
    """Compute negative log-likelihood of an observation under a von Mises model.

    Higher values = the login hour is more anomalous relative to the user's
    historical distribution.

    If κ = 0 (flat prior / cold start), returns 0.0 (no signal).

    Parameters
    ----------
    hour:
        Login hour in [0, 24).
    model:
        Fitted VonMisesModel for this user.

    Returns
    -------
    float
        Negative log-likelihood ≥ 0.
    """
    if model.kappa < 1e-9:
        return 0.0  # flat prior: no signal

    theta = (_TWO_PI * hour) / 24.0
    # Correct NLL = log(2π) + log(I₀(κ)) − κ·cos(θ − μ)
    #
    # The log(2π) term is the partition function contribution and is required
    # to make NLL values comparable across users with different κ values.
    # Without it, Alice (κ=5) and Bob (κ=50) cannot be compared on the same
    # scale — a score of 3.2 for Alice means something completely different
    # than 3.2 for Bob.
    log_i0 = _log_bessel_i0(model.kappa)
    nll = _LOG_TWO_PI + log_i0 - model.kappa * math.cos(theta - model.mu)
    return max(0.0, nll)


class VonMisesBaseline:
    """Per-user von Mises baseline: fits and stores models for all users.

    Parameters
    ----------
    min_samples:
        Minimum login count to fit a model. Below this, flat prior is used.
    """

    def __init__(self, min_samples: int = _MIN_VM_SAMPLES) -> None:
        self.min_samples = min_samples
        self._models: dict[str, VonMisesModel] = {}

    def fit(self, events: list[dict], user_key: str = "user_id") -> "VonMisesBaseline":
        """Fit von Mises models for all users in the event list.

        Parameters
        ----------
        events:
            List of event dicts with ``user_key`` and a timestamp field.
        user_key:
            Field name for the user identifier.
        """
        from collections import defaultdict

        user_hours: dict[str, list[float]] = defaultdict(list)

        for ev in events:
            user = ev.get(user_key, ev.get("username", "unknown"))
            ts = ev.get("timestamp", ev.get("event_time"))
            if ts is None:
                continue
            try:
                if hasattr(ts, "hour"):
                    hour = float(ts.hour) + float(ts.minute) / 60.0
                elif isinstance(ts, str):
                    from datetime import datetime
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    hour = dt.hour + dt.minute / 60.0
                else:
                    hour = float(ts) % 24.0
                user_hours[user].append(hour)
            except (ValueError, AttributeError, TypeError):
                continue

        fitted = 0
        for user, hours in user_hours.items():
            self._models[user] = fit_von_mises(np.array(hours))
            if self._models[user].kappa > 0:
                fitted += 1

        logger.info(
            "[von_mises] Baseline fitted: %d users, %d with κ > 0.",
            len(self._models), fitted,
        )
        return self

    def anomaly_prior(self, user: str, hour: float) -> float:
        """Return the von Mises NLL for a login as a prior anomaly signal.

        Returns
        -------
        float
            NLL ≥ 0. 0.0 for unknown users or cold-start users (κ = 0).
        """
        model = self._models.get(user)
        if model is None:
            return 0.0
        return von_mises_nll(hour, model)

    def get_model(self, user: str) -> Optional[VonMisesModel]:
        return self._models.get(user)

    def is_fitted(self, user: str) -> bool:
        m = self._models.get(user)
        return m is not None and m.kappa > 0

    def fitted_users(self) -> list[str]:
        return list(self._models.keys())


# ------------------------------------------------------------------
# Private math helpers
# ------------------------------------------------------------------

def _A_kappa(kappa: float) -> float:
    """Compute A(κ) = I₁(κ)/I₀(κ), the ratio used in von Mises MLE.

    Uses scipy scaled Bessel functions (i1e, i0e) to avoid overflow for large κ.
    i1e(x) = I₁(x)·exp(-x), i0e(x) = I₀(x)·exp(-x), so their ratio = I₁/I₀.
    Falls back to series approximation if scipy is unavailable.
    """
    if kappa < 1e-9:
        return 0.0
    try:
        from scipy.special import i0e, i1e
        i0_val = float(i0e(kappa))
        i1_val = float(i1e(kappa))
        if i0_val < 1e-300:
            return 1.0  # A(κ) → 1 as κ → ∞
        return i1_val / i0_val
    except ImportError:
        # Approximation: A(κ) ≈ 1 - 1/(2κ) for large κ
        if kappa > 10.0:
            return 1.0 - 1.0 / (2.0 * kappa)
        # For small κ, A(κ) ≈ κ/2 - κ³/16 (series expansion)
        return kappa / 2.0 - kappa**3 / 16.0


def _estimate_kappa_nr(R_bar: float) -> float:
    """Estimate von Mises κ from mean resultant length R̄ via Newton-Raphson.

    Numerically inverts A(κ) = R̄ where A(κ) = I₁(κ)/I₀(κ).
    Converges in 3–8 iterations for all R̄ ∈ (0, 1). Smooth everywhere —
    no branch discontinuities unlike the Mardia & Jupp lookup table.

    The result is capped at _KAPPA_MAX=200 to prevent numerical issues for
    near-deterministic users (e.g., R̄ = 0.9999 → κ ≈ 10³ → NLL blow-up).
    """
    if R_bar < 1e-9:
        return 0.0
    R_bar = min(R_bar, 1.0 - 1e-9)

    # Initial guess from Mardia & Jupp approximation (3-branch, warm start)
    if R_bar < 0.53:
        kappa = 2.0 * R_bar + R_bar**3 + (5.0 * R_bar**5) / 6.0
    elif R_bar < 0.85:
        kappa = -0.4 + 1.39 * R_bar + 0.43 / (1.0 - R_bar)
    else:
        kappa = 1.0 / (R_bar**3 - 4.0 * R_bar**2 + 3.0 * R_bar)
    kappa = max(kappa, 1e-9)

    # Newton-Raphson iterations: f(κ) = A(κ) − R̄, f'(κ) = 1 − A(κ)² − A(κ)/κ
    for _ in range(12):
        A = _A_kappa(kappa)
        residual = A - R_bar
        if abs(residual) < 1e-8:
            break
        # Derivative of A(κ) w.r.t. κ
        dA = max(1.0 - A**2 - A / kappa, 1e-12)  # always positive, guard zero
        kappa -= residual / dA
        kappa = max(kappa, 1e-9)

    return min(kappa, _KAPPA_MAX)


def _estimate_kappa(R_bar: float) -> float:
    """Legacy Mardia & Jupp lookup approximation (kept for reference).

    .. deprecated::
        Use :func:`_estimate_kappa_nr` instead. This function has branch
        discontinuities at R̄=0.53 and R̄=0.85 that can cause sudden
        anomaly score jumps when a user's login count crosses those thresholds.
    """
    if R_bar < 0.53:
        return 2.0 * R_bar + R_bar ** 3 + (5.0 * R_bar ** 5) / 6.0
    elif R_bar < 0.85:
        return -0.4 + 1.39 * R_bar + 0.43 / (1.0 - R_bar)
    else:
        return 1.0 / (R_bar ** 3 - 4.0 * R_bar ** 2 + 3.0 * R_bar)


def _log_bessel_i0(x: float) -> float:
    """Compute log(I₀(x)) without overflow.

    For large x, I₀(x) ≈ exp(x) / sqrt(2πx), so log(I₀(x)) ≈ x - 0.5·log(2πx).
    For small-to-medium x, use scipy if available, else a polynomial approximation.
    """
    if x < 1e-6:
        return 0.0  # log(I0(0)) = log(1) = 0

    # Large-x regime: log-space approximation avoids exp(x) → inf
    if x > 700.0:
        return float(x - 0.5 * math.log(_TWO_PI * x))

    try:
        from scipy.special import i0e  # i0e(x) = I0(x) * exp(-x)
        # log(I0) = log(i0e) + x
        i0e_val = float(i0e(x))
        if i0e_val > 0:
            return math.log(i0e_val) + x
        # fallthrough to approximation
    except ImportError:
        pass

    # Large-x approximation: safe for x > 3.75
    if x > 3.75:
        return float(x - 0.5 * math.log(_TWO_PI * x))

    # Small x polynomial (Abramowitz & Stegun 9.8.1)
    t = (x / 3.75) ** 2
    i0 = (1.0 + 3.5156229 * t + 3.0899424 * t ** 2 + 1.2067492 * t ** 3 +
          0.2659732 * t ** 4 + 0.0360768 * t ** 5 + 0.0045813 * t ** 6)
    return math.log(max(i0, 1e-300))


def _bessel_i0(x: float) -> float:
    """Modified Bessel function I₀(x), computed via scipy or polynomial fallback."""
    try:
        from scipy.special import i0
        return float(i0(x))
    except ImportError:
        # Polynomial approximation (Abramowitz & Stegun 9.8.1) for x ≤ 3.75
        if x <= 3.75:
            t = (x / 3.75) ** 2
            return 1.0 + 3.5156229 * t + 3.0899424 * t**2 + 1.2067492 * t**3 + \
                   0.2659732 * t**4 + 0.0360768 * t**5 + 0.0045813 * t**6
        else:
            return math.exp(x) / math.sqrt(_TWO_PI * x)

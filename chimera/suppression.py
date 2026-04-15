"""
chimera.suppression — Multi-signal false positive gate (v0.4.2).

False positives are the primary reason anomaly detection systems get disabled.
A naive threshold crossing → alert pipeline generates too many single-signal
spikes that are statistically normal variance, not actual attacks.

Security hardening (v0.4.2)
----------------------------
**Hard bypass floor (A3)**: A ``hard_score_floor`` parameter ensures that
extreme anomalies (score >= floor, default 0.97) ALWAYS generate an alert,
regardless of multi-signal gate logic. An adversary who carefully crafts
activity to fire only one signal cannot exploit the gate when their score
is exceptionally high.

**Sub-event accumulation (D2)**: Within the deduplication window, suppressed
events are accumulated in a burst log. The emitted alert includes a
``suppressed_count`` field showing how many events were suppressed so an
analyst always sees the full scope of a burst attack, not just the first event.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Triage model protocol (Future Phase 7)
# ------------------------------------------------------------------

@runtime_checkable
class TriageModel(Protocol):
    """Interface for offline AI triage. Implementations: LLM and ONNX."""
    def triage(self, alert_context: dict) -> "TriageResult": ...


@dataclass
class TriageResult:
    """AI triage output."""
    fp_probability: float
    confidence: float
    reasoning: str
    model_id: str


@dataclass
class BurstSummary:
    """Emitted after a dedup window when sub-events were suppressed (D2 fix).

    Gives analysts full visibility into rapid attack bursts.
    """
    user: str
    window_start: str
    window_end: str
    total_events: int
    suppressed_count: int
    max_score: float
    signals_seen: list


# ------------------------------------------------------------------
# Suppression gate
# ------------------------------------------------------------------

@dataclass
class SignalEvaluation:
    """Result of evaluating one anomaly event against all signals."""
    ensemble_fired: bool
    temporal_fired: bool
    jsd_fired: bool
    triage_fp_prob: float = 0.0
    hard_bypass: bool = False       # True when hard_score_floor triggered

    @property
    def signals_firing(self) -> list:
        signals = []
        if self.ensemble_fired:
            signals.append("ensemble_score")
        if self.temporal_fired:
            signals.append("temporal_nll")
        if self.jsd_fired:
            signals.append("model_disagreement")
        if self.hard_bypass:
            signals.append("hard_floor_bypass")
        return signals

    @property
    def n_signals(self) -> int:
        return len(self.signals_firing)


class FPSuppressor:
    """Multi-signal false positive gate.

    An alert is emitted only when ``min_signals`` independent anomaly channels
    agree. Single-signal spikes are logged quietly at DEBUG level.

    Security hardening (v0.4.2):
    - ``hard_score_floor``: extreme anomaly scores bypass gate logic entirely.
    - Dedup window accumulates sub-events into BurstSummary so analysts see
      the full scope of rapid attack bursts.

    Parameters
    ----------
    min_signals:
        Minimum signals that must agree. Default: 2.
    hard_score_floor:
        Scores >= this value bypass the multi-signal gate entirely.
        Default: 0.97. Set to 1.0 to disable.
    jsd_floor:
        Minimum JSD to count as model-disagreement signal.
    vm_nll_percentile:
        User NLL percentile threshold for the temporal signal.
    dedup_window_seconds:
        Suppress duplicate alerts for the same user within this window.
    dedup_max_per_window:
        Max alerts per user per window before dedup kicks in.
    triage_model:
        Optional offline AI triage model (Phase 7).
    """

    def __init__(
        self,
        min_signals: int = 2,
        hard_score_floor: float = 0.97,
        jsd_floor: float = 0.2,
        vm_nll_percentile: float = 95.0,
        dedup_window_seconds: float = 60.0,
        dedup_max_per_window: int = 3,
        triage_fp_threshold: float = 0.80,
        triage_model: Optional[TriageModel] = None,
    ) -> None:
        if not 1 <= min_signals <= 3:
            raise ValueError(f"min_signals must be 1-3; got {min_signals}")
        if not 0.0 < hard_score_floor <= 1.0:
            raise ValueError(f"hard_score_floor must be in (0, 1]; got {hard_score_floor}")
        self.min_signals = min_signals
        self.hard_score_floor = hard_score_floor
        self.jsd_floor = jsd_floor
        self.vm_nll_percentile = vm_nll_percentile
        self.dedup_window_seconds = dedup_window_seconds
        self.dedup_max_per_window = dedup_max_per_window
        self.triage_fp_threshold = triage_fp_threshold
        self.triage_model = triage_model

        # Per-user NLL history for percentile computation
        self._nll_history: dict = defaultdict(lambda: deque(maxlen=500))

        # Deduplication state: user -> deque of (timestamp, score, signals)
        self._dedup_log: dict = defaultdict(lambda: deque(maxlen=200))

        # Burst accumulation: user -> {count, max_score, signals_seen, window_start}
        self._burst_log: dict = {}

        self.n_evaluated: int = 0
        self.n_suppressed: int = 0
        self.n_emitted: int = 0

    def record_nll(self, user: str, nll: float) -> None:
        """Record a von Mises NLL observation for a user's historical distribution."""
        self._nll_history[user].append(nll)

    def evaluate(
        self,
        user: str,
        score: float,
        threshold: float,
        vm_nll: float,
        jsd: float,
        event: Optional[dict] = None,
    ) -> "tuple[bool, SignalEvaluation]":
        """Evaluate an anomalous event against the multi-signal gate.

        Returns
        -------
        (should_emit, evaluation)
        """
        self.n_evaluated += 1

        # --- Hard bypass (A3): extreme anomalies ALWAYS alert ---
        if score >= self.hard_score_floor:
            evaluation = SignalEvaluation(
                ensemble_fired=True,
                temporal_fired=False,
                jsd_fired=False,
                hard_bypass=True,
            )
            self.n_emitted += 1
            logger.warning(
                "[suppressor] HARD BYPASS: score=%.4f >= floor=%.4f for user %s. "
                "Gate skipped — extreme anomaly always alerts.",
                score, self.hard_score_floor, user,
            )
            return True, evaluation

        # Signal 1: ensemble score threshold crossing
        ensemble_fired = score >= threshold

        # Signal 2: temporal anomaly
        nll_hist = list(self._nll_history[user])
        if len(nll_hist) >= 10:
            import numpy as np
            nll_threshold = float(np.percentile(nll_hist, self.vm_nll_percentile))
            temporal_fired = vm_nll > nll_threshold
        else:
            temporal_fired = False

        # Signal 3: model disagreement
        jsd_fired = jsd >= self.jsd_floor

        evaluation = SignalEvaluation(
            ensemble_fired=ensemble_fired,
            temporal_fired=temporal_fired,
            jsd_fired=jsd_fired,
        )

        # Triage model (Phase 7)
        triage_suppressed = False
        if self.triage_model is not None and evaluation.n_signals >= self.min_signals:
            try:
                ctx = {"user": user, "score": score, "threshold": threshold,
                       "vm_nll": vm_nll, "jsd": jsd, "event": event}
                result = self.triage_model.triage(ctx)
                evaluation.triage_fp_prob = result.fp_probability
                if result.fp_probability >= self.triage_fp_threshold:
                    triage_suppressed = True
                    logger.info(
                        "[suppressor] AI triage suppressed alert for %s: "
                        "fp_prob=%.2f reasoning=%s",
                        user, result.fp_probability, result.reasoning,
                    )
            except Exception:
                logger.exception("[suppressor] Triage model raised — ignoring")

        should_emit = (
            evaluation.n_signals >= self.min_signals
            and not triage_suppressed
        )

        # Dedup check (D2: accumulates sub-events)
        if should_emit:
            should_emit = self._check_dedup(user, score, evaluation.signals_firing)

        if should_emit:
            self.n_emitted += 1
            logger.debug("[suppressor] Alert emitted for %s: signals=%s",
                         user, evaluation.signals_firing)
        else:
            self.n_suppressed += 1
            # Only accumulate burst if at least 1 signal fired (not zero-signal gate suppression)
            if evaluation.n_signals > 0:
                self._accumulate_burst(user, score, evaluation.signals_firing)
                logger.debug(
                    "[suppressor] Alert suppressed for %s: n_signals=%d/%d signals=%s",
                    user, evaluation.n_signals, self.min_signals, evaluation.signals_firing,
                )

        return should_emit, evaluation

    def flush_burst_summary(self, user: str) -> Optional[BurstSummary]:
        """Return and clear any pending burst summary for a user (D2).

        Call after emitting an alert to check if suppressed sub-events exist.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        burst = self._burst_log.pop(user, None)
        if burst is None or burst.get("count", 0) == 0:
            return None
        return BurstSummary(
            user=user,
            window_start=burst.get("window_start", now_str),
            window_end=now_str,
            total_events=burst["count"] + 1,
            suppressed_count=burst["count"],
            max_score=burst["max_score"],
            signals_seen=list(burst["signals_seen"]),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_dedup(self, user: str, score: float, signals: list) -> bool:
        """Check deduplication window. Returns True if alert should proceed."""
        now = time.monotonic()
        log = self._dedup_log[user]

        # Prune old entries outside the window
        while log and (now - log[0][0]) > self.dedup_window_seconds:
            log.popleft()

        if len(log) >= self.dedup_max_per_window:
            logger.debug(
                "[suppressor] Dedup suppressed for %s: %d alerts in %.0fs window",
                user, len(log), self.dedup_window_seconds,
            )
            self._accumulate_burst(user, score, signals)
            return False

        log.append((now, score, signals))
        return True

    def _accumulate_burst(self, user: str, score: float, signals: list) -> None:
        """Record a suppressed event in the burst accumulator (D2)."""
        if user not in self._burst_log:
            self._burst_log[user] = {
                "count": 0,
                "max_score": score,
                "signals_seen": set(),
                "window_start": datetime.now(timezone.utc).isoformat(),
            }
        burst = self._burst_log[user]
        burst["count"] += 1
        burst["max_score"] = max(burst["max_score"], score)
        burst["signals_seen"].update(signals)

    @property
    def suppression_rate(self) -> float:
        """Fraction of evaluated events that were suppressed."""
        if self.n_evaluated == 0:
            return 0.0
        return self.n_suppressed / self.n_evaluated

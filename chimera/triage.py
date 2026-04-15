"""
chimera.triage — Offline ONNX alert pre-classifier (Phase 7 MVP).

Implements the TriageModel Protocol from chimera.suppression using a
lightweight ONNX binary classifier trained on Chimera's own alert history.

How it works
------------
The classifier receives a feature vector derived from the alert context:
    - ensemble_score (float)
    - threshold (float)
    - excess_ratio  = (score - threshold) / threshold
    - jsd           (float)
    - vm_nll        (float)
    - n_signals     (int)
    - hour_sin/cos  (time of day cyclic features)
    - is_weekend    (bool)

Output: fp_probability ∈ [0, 1]
    0.0 = almost certainly a true positive
    1.0 = almost certainly a false positive

Training
--------
The model is trained offline via `chimera triage train --feedback <ndjson>`.
It reads the analyst feedback NDJSON log, builds features from the alert
context, and trains a gradient-boosted binary classifier (XGBoost → ONNX
export). Training requires ~100 labelled alerts for useful performance;
above 500 labels it typically achieves > 90% FP detection rate.

Retrain after any major operational change (new detector added, new
user population, network topology change).

Model file
----------
Default location: `<model_dir>/triage_model.onnx` (~50–200 MB).
Can be specified via the `--triage-model` CLI flag or
`triage.model_path` in the config file.

This file only contains inference code. Training is in `benchmarks/triage_train.py`.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TriageResult:
    """AI triage classification result."""
    fp_probability: float   # 0.0 = TP, 1.0 = FP
    confidence: float       # model's self-reported confidence
    reasoning: str          # human-readable explanation
    model_id: str           # model identifier


def _build_feature_vector(alert_context: dict) -> list[float]:
    """Extract features from an alert context dict."""
    import datetime

    score = float(alert_context.get("score", 0.0))
    threshold = float(alert_context.get("threshold", 1.0))
    jsd = float(alert_context.get("jsd", 0.0))
    vm_nll = float(alert_context.get("vm_nll", 0.0))
    n_signals = float(len(alert_context.get("signals_firing", [])))
    excess_ratio = (score - threshold) / max(threshold, 1e-9)

    # Time features (from raw event if available)
    hour = 12.0  # default noon
    is_weekend = 0.0
    event = alert_context.get("event", {})
    ts = event.get("timestamp") or event.get("event_time")
    if ts is not None:
        try:
            if hasattr(ts, "hour"):
                hour = float(ts.hour) + float(ts.minute) / 60.0
                is_weekend = float(ts.weekday() >= 5)
            elif isinstance(ts, str):
                dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour = dt.hour + dt.minute / 60.0
                is_weekend = float(dt.weekday() >= 5)
        except Exception:
            pass

    two_pi = 2.0 * math.pi
    hour_sin = math.sin(two_pi * hour / 24.0)
    hour_cos = math.cos(two_pi * hour / 24.0)

    return [
        score,
        threshold,
        excess_ratio,
        jsd,
        vm_nll,
        n_signals,
        hour_sin,
        hour_cos,
        is_weekend,
    ]


class ONNXTriageModel:
    """Offline ONNX binary FP/TP classifier.

    Implements the :class:`chimera.suppression.TriageModel` Protocol.

    Parameters
    ----------
    model_path:
        Path to the ``.onnx`` model file (see module docstring for training).
    fp_threshold:
        Probability above which an alert is classified as FP.
        Default 0.80 — requires 80% FP confidence before suppressing.
    """

    def __init__(
        self,
        model_path: str | Path,
        fp_threshold: float = 0.80,
    ) -> None:
        self.model_path = Path(model_path)
        self.fp_threshold = fp_threshold
        self._session = None
        self._load_model()

    def _load_model(self) -> None:
        """Load the ONNX runtime session."""
        try:
            import onnxruntime as ort  # type: ignore
        except ImportError:
            raise ImportError(
                "onnxruntime is required for ONNX triage. "
                "Install with: pip install onnxruntime"
            )

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"ONNX triage model not found: {self.model_path}. "
                "Train it with: chimera triage train --feedback <feedback.ndjson>"
            )

        # CPU-only inference — no GPU needed for this use case
        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 2
        self._session = ort.InferenceSession(
            str(self.model_path),
            sess_options=opts,
            providers=["CPUExecutionProvider"],
        )
        self._input_name = self._session.get_inputs()[0].name
        logger.info("[triage] ONNX model loaded from %s", self.model_path)

    def triage(self, alert_context: dict) -> TriageResult:
        """Classify one alert as TP or FP.

        Parameters
        ----------
        alert_context:
            Dict with keys: ``score``, ``threshold``, ``jsd``, ``vm_nll``,
            ``signals_firing`` (list), ``event`` (raw event dict).

        Returns
        -------
        TriageResult
            ``fp_probability`` ∈ [0, 1].
        """
        import numpy as np

        features = _build_feature_vector(alert_context)
        X = np.array([features], dtype=np.float32)

        outputs = self._session.run(None, {self._input_name: X})
        # ONNX classifiers typically output [class_labels, probabilities]
        # probabilities shape: (1, 2) — [P(TP), P(FP)]
        if len(outputs) >= 2:
            probs = outputs[1]
            fp_prob = float(probs[0][1]) if probs.shape[1] >= 2 else float(probs[0][0])
        else:
            # Regression output (single value = FP probability)
            fp_prob = float(outputs[0][0])

        fp_prob = max(0.0, min(1.0, fp_prob))
        confidence = abs(fp_prob - 0.5) * 2.0  # [0, 1] — 0 = maximally uncertain

        verdict = "FP" if fp_prob >= self.fp_threshold else "TP"
        reasoning = (
            f"ONNX classifier: fp_prob={fp_prob:.3f} "
            f"({'above' if fp_prob >= self.fp_threshold else 'below'} "
            f"threshold={self.fp_threshold}). "
            f"Verdict: {verdict}."
        )

        return TriageResult(
            fp_probability=fp_prob,
            confidence=confidence,
            reasoning=reasoning,
            model_id=f"onnx:{self.model_path.stem}",
        )

    @property
    def is_loaded(self) -> bool:
        return self._session is not None

    def __repr__(self) -> str:
        return (
            f"ONNXTriageModel(model={self.model_path.name!r}, "
            f"fp_threshold={self.fp_threshold}, "
            f"loaded={self.is_loaded})"
        )


def load_triage_model(
    model_path: str | Path,
    fp_threshold: float = 0.80,
    manifest: Optional[object] = None,
) -> ONNXTriageModel:
    """Load and optionally integrity-verify an ONNX triage model.

    Parameters
    ----------
    model_path:
        Path to the ``.onnx`` file.
    fp_threshold:
        FP classification probability threshold.
    manifest:
        Optional :class:`chimera.engine.integrity.IntegrityManifest`.
        If provided, the ONNX file is SHA-256 verified before loading.
    """
    path = Path(model_path)

    if manifest is not None:
        from chimera.engine.integrity import IntegrityManifest
        if isinstance(manifest, IntegrityManifest):
            manifest.require_valid(path)

    return ONNXTriageModel(model_path=path, fp_threshold=fp_threshold)

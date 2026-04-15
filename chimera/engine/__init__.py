"""
chimera.engine — Robustness-first scoring engine for Chimera v0.3.

Modules:
    normalizer  — Per-model score normalization with degenerate-distribution guards.
    voter       — Ensemble voting (mean/median/trimmed/weighted) + disagreement entropy.
    threshold   — Contamination-percentile thresholding + drift tracking (Δτ).
    pipeline    — Orchestrates normalizer → voter → threshold in one call.
    integrity   — SHA-256 integrity probes for model and config files.
"""
from chimera.engine.normalizer import ScoreNormalizer, InsufficientDataError
from chimera.engine.voter import EnsembleVoter
from chimera.engine.threshold import DynamicThreshold
from chimera.engine.pipeline import EnginePipeline

__all__ = [
    "ScoreNormalizer",
    "InsufficientDataError",
    "EnsembleVoter",
    "DynamicThreshold",
    "EnginePipeline",
]

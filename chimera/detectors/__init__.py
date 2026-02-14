"""
Built-in anomaly detectors for Chimera.

Provides multiple detection algorithms through a common interface:
- Isolation Forest (primary)
- Local Outlier Factor
- Ensemble voting across multiple detectors
"""

from chimera.detectors.base import BaseDetector
from chimera.detectors.isolation_forest import IsolationForestDetector
from chimera.detectors.lof import LOFDetector
from chimera.detectors.ensemble import EnsembleDetector

__all__ = [
    "BaseDetector",
    "IsolationForestDetector",
    "LOFDetector",
    "EnsembleDetector",
]

"""
Chimera — Behavioral Anomaly Detection for Authentication Logs.

An open-source, offline-first tool that uses unsupervised machine
learning and deterministic rules to identify suspicious authentication
patterns without requiring labeled data.
"""

__version__ = "0.2.0"
__author__ = "Chimera Contributors"
__license__ = "MIT"

# Core components
from chimera.data_loader import AuthEvent, AuthLogLoader
from chimera.feature_engineering import FeatureEngineer, UserBehaviorProfile
from chimera.model import AnomalyDetector, ModelConfig
from chimera.scoring import AnomalyScorer, AnomalyResult, UserSummary
from chimera.reporting import ReportGenerator

# v0.2 components
from chimera.registry import DetectorRegistry
from chimera.config import ChimeraConfig
from chimera.correlator import EventCorrelator
from chimera.exporters import CEFExporter, SyslogExporter, STIXExporter
from chimera.detectors import (
    BaseDetector,
    IsolationForestDetector,
    LOFDetector,
    EnsembleDetector,
)

__all__ = [
    # Core
    "AuthEvent",
    "AuthLogLoader",
    "FeatureEngineer",
    "UserBehaviorProfile",
    "AnomalyDetector",
    "ModelConfig",
    "AnomalyScorer",
    "AnomalyResult",
    "UserSummary",
    "ReportGenerator",
    # v0.2
    "DetectorRegistry",
    "ChimeraConfig",
    "EventCorrelator",
    "BaseDetector",
    "IsolationForestDetector",
    "LOFDetector",
    "EnsembleDetector",
    "CEFExporter",
    "SyslogExporter",
    "STIXExporter",
]

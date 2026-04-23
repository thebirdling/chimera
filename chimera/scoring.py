"""
Scoring module for anomaly detection results.

Provides anomaly scoring, thresholding, and per-user summaries
with explainable output.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Any
from collections import defaultdict
import logging

import numpy as np
import pandas as pd

from chimera.model import AnomalyDetector
from chimera.data_loader import AuthEvent

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """
    Result of anomaly detection for a single event.
    
    Contains the anomaly score, classification, and explanation.
    """
    # Event identification
    event_index: int
    user_id: str
    timestamp: datetime
    event_type: str
    
    # Anomaly scoring
    anomaly_score: float
    is_anomaly: bool
    confidence: float  # 0-1 scale
    
    # Explanation
    top_contributing_features: list[dict[str, Any]] = field(default_factory=list)
    research_signals: dict[str, float] = field(default_factory=dict)
    research_reasons: list[str] = field(default_factory=list)
    
    # Context
    user_baseline_score: float = 0.0
    global_percentile: float = 0.0
    
    # Raw data reference
    raw_event: Optional[AuthEvent] = field(default=None, repr=False)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "event_index": self.event_index,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "anomaly_score": round(self.anomaly_score, 6),
            "is_anomaly": self.is_anomaly,
            "confidence": round(self.confidence, 4),
            "top_contributing_features": self.top_contributing_features,
            "research_signals": self.research_signals,
            "research_reasons": self.research_reasons,
            "user_baseline_score": round(self.user_baseline_score, 6),
            "global_percentile": round(self.global_percentile, 4),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnomalyResult":
        """Create an AnomalyResult from a dictionary."""
        ts = data.get("timestamp")
        if isinstance(ts, str):
            from dateutil.parser import parse as parse_dt
            try:
                ts = parse_dt(ts)
            except Exception:
                ts = datetime.fromisoformat(ts)
        return cls(
            event_index=data.get("event_index", 0),
            user_id=data.get("user_id", ""),
            timestamp=ts,
            event_type=data.get("event_type", ""),
            anomaly_score=data.get("anomaly_score", 0.0),
            is_anomaly=data.get("is_anomaly", False),
            confidence=data.get("confidence", 0.0),
            top_contributing_features=data.get("top_contributing_features", []),
            research_signals=data.get("research_signals", {}),
            research_reasons=data.get("research_reasons", []),
            user_baseline_score=data.get("user_baseline_score", 0.0),
            global_percentile=data.get("global_percentile", 0.0),
        )

    def explain(self) -> str:
        """Generate a human-readable explanation of the anomaly."""
        if not self.is_anomaly:
            return f"Normal event for user {self.user_id}"
        
        explanation = f"ANOMALY DETECTED for user {self.user_id} at {self.timestamp}\n"
        explanation += f"  Anomaly Score: {self.anomaly_score:.4f} (confidence: {self.confidence:.2%})\n"
        explanation += f"  Event Type: {self.event_type}\n"
        explanation += f"  Global Percentile: {self.global_percentile:.2%}\n"
        
        if self.top_contributing_features:
            explanation += "  Top Contributing Factors:\n"
            for i, feat in enumerate(self.top_contributing_features[:3], 1):
                explanation += f"    {i}. {feat['feature']}: z-score={feat['z_score']:.2f}\n"

        if self.research_reasons:
            explanation += "  Identity Research Signals:\n"
            for reason in self.research_reasons[:3]:
                explanation += f"    - {reason}\n"

        return explanation


@dataclass
class UserSummary:
    """
    Summary of anomaly detection results for a single user.
    """
    user_id: str
    total_events: int = 0
    anomaly_count: int = 0
    anomaly_rate: float = 0.0
    
    # Score statistics
    mean_score: float = 0.0
    min_score: float = 0.0
    max_score: float = 0.0
    score_std: float = 0.0
    
    # Temporal patterns
    first_event: Optional[datetime] = None
    last_event: Optional[datetime] = None
    
    # Risk assessment
    risk_level: str = "unknown"  # low, medium, high, critical
    
    # Anomalous events
    anomalous_event_indices: list[int] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            "user_id": self.user_id,
            "total_events": self.total_events,
            "anomaly_count": self.anomaly_count,
            "anomaly_rate": round(self.anomaly_rate, 4),
            "mean_score": round(self.mean_score, 6),
            "min_score": round(self.min_score, 6),
            "max_score": round(self.max_score, 6),
            "score_std": round(self.score_std, 6),
            "first_event": self.first_event.isoformat() if self.first_event else None,
            "last_event": self.last_event.isoformat() if self.last_event else None,
            "risk_level": self.risk_level,
            "anomalous_event_indices": self.anomalous_event_indices,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UserSummary":
        """Create a UserSummary from a dictionary."""
        first_event = data.get("first_event")
        last_event = data.get("last_event")
        if isinstance(first_event, str):
            from dateutil.parser import parse as parse_dt
            try:
                first_event = parse_dt(first_event)
            except Exception:
                first_event = None
        if isinstance(last_event, str):
            from dateutil.parser import parse as parse_dt
            try:
                last_event = parse_dt(last_event)
            except Exception:
                last_event = None
        return cls(
            user_id=data.get("user_id", ""),
            total_events=data.get("total_events", 0),
            anomaly_count=data.get("anomaly_count", 0),
            anomaly_rate=data.get("anomaly_rate", 0.0),
            mean_score=data.get("mean_score", 0.0),
            min_score=data.get("min_score", 0.0),
            max_score=data.get("max_score", 0.0),
            score_std=data.get("score_std", 0.0),
            first_event=first_event,
            last_event=last_event,
            risk_level=data.get("risk_level", "unknown"),
            anomalous_event_indices=data.get("anomalous_event_indices", []),
        )


class AnomalyScorer:
    """
    Scoring engine for anomaly detection results.
    
    Provides:
    - Anomaly score calculation and thresholding
    - Per-event explanations
    - Per-user summaries
    - Risk assessment
    """
    
    # Risk level thresholds
    RISK_LOW = "low"
    RISK_MEDIUM = "medium"
    RISK_HIGH = "high"
    RISK_CRITICAL = "critical"
    
    # Risk Thresholds
    CRITICAL_RATE_THRESHOLD = 0.5
    CRITICAL_SCORE_THRESHOLD = -0.5
    HIGH_RATE_THRESHOLD = 0.2
    HIGH_SCORE_THRESHOLD = -0.1
    MEDIUM_RATE_THRESHOLD = 0.05
    
    def __init__(
        self, 
        threshold: Optional[float] = None,
        auto_threshold: bool = True,
        contamination: float = 0.1,
        identity_hard_floor: Optional[float] = None,
        identity_hard_floor_column: str = "identity_takeover_score",
        identity_hard_floor_support_column: Optional[str] = "identity_takeover_support",
        identity_hard_floor_support_threshold: float = 0.55,
    ):
        """
        Initialize the anomaly scorer.
        
        Args:
            threshold: Fixed threshold for anomaly classification.
                      If None, uses percentile-based thresholding.
            auto_threshold: Whether to automatically determine threshold
            contamination: Expected proportion of anomalies (for auto-threshold)
        """
        self.threshold = threshold
        self.auto_threshold = auto_threshold
        self.contamination = contamination
        self.identity_hard_floor = identity_hard_floor
        self.identity_hard_floor_column = identity_hard_floor_column
        self.identity_hard_floor_support_column = identity_hard_floor_support_column
        self.identity_hard_floor_support_threshold = identity_hard_floor_support_threshold
        self._score_stats: Optional[dict[str, float]] = None
    
    def score(
        self,
        events: list[AuthEvent],
        features_df: pd.DataFrame,
        detector: AnomalyDetector,
    ) -> list[AnomalyResult]:
        """
        Score all events for anomalies.
        
        Args:
            events: Original authentication events
            features_df: Engineered features DataFrame
            detector: Trained anomaly detector
            
        Returns:
            List of AnomalyResult objects
        """
        logger.info(f"Scoring {len(events)} events for anomalies")
        
        # Get numeric features for scoring
        numeric_features = features_df.select_dtypes(include=[np.number])
        numeric_features = numeric_features.fillna(0)
        if getattr(detector, "feature_names", None):
            numeric_features = numeric_features.reindex(
                columns=list(detector.feature_names),
                fill_value=0,
            )
        
        # Calculate anomaly scores
        scores = detector.score(numeric_features)
        
        # Determine threshold
        if self.threshold is None and self.auto_threshold:
            self.threshold = np.percentile(scores, self.contamination * 100)
        elif self.threshold is None:
            self.threshold = 0.0
        
        # Calculate score statistics
        self._score_stats = {
            "mean": float(np.mean(scores)),
            "std": float(np.std(scores)),
            "min": float(np.min(scores)),
            "max": float(np.max(scores)),
            "median": float(np.median(scores)),
        }
        
        # Get feature explanations
        explanations = detector.explain_features(numeric_features, top_k=5)
        
        # Build results
        results = []
        for i, (event, score, explanation) in enumerate(zip(events, scores, explanations)):
            feature_row = features_df.iloc[i]
            identity_floor_hit = self._identity_floor_hit(feature_row)
            is_anomaly = score < self.threshold or identity_floor_hit
            
            # Calculate confidence based on distance from threshold
            if is_anomaly:
                confidence = min(1.0, (self.threshold - score) / max(abs(self.threshold), 0.1))
            else:
                confidence = min(1.0, (score - self.threshold) / max(abs(self.threshold), 0.1))
            
            # Calculate percentile
            percentile = np.mean(scores <= score)
            
            result = AnomalyResult(
                event_index=i,
                user_id=event.user_id,
                timestamp=event.timestamp,
                event_type=event.event_type,
                anomaly_score=float(score),
                is_anomaly=is_anomaly,
                confidence=float(confidence),
                top_contributing_features=explanation["top_features"],
                global_percentile=float(percentile),
                raw_event=event,
            )
            self._attach_research_context(result, feature_row)
            if identity_floor_hit:
                result.research_reasons = [
                    f"Identity fusion hard floor triggered at {self.identity_hard_floor:.2f}."
                ] + result.research_reasons
            results.append(result)
        
        # Calculate per-user baseline scores
        self._calculate_user_baselines(results)
        
        logger.info(f"Scoring complete. Anomalies detected: {sum(r.is_anomaly for r in results)}")
        
        return results
    
    def summarize_by_user(self, results: list[AnomalyResult]) -> list[UserSummary]:
        """
        Generate per-user summaries from anomaly results.
        
        Args:
            results: List of AnomalyResult objects
            
        Returns:
            List of UserSummary objects
        """
        # Group results by user
        user_results: dict[str, list[AnomalyResult]] = defaultdict(list)
        for result in results:
            user_results[result.user_id].append(result)
        
        summaries = []
        for user_id, user_events in user_results.items():
            summary = self._create_user_summary(user_id, user_events)
            summaries.append(summary)
        
        # Sort by risk level (critical first)
        risk_order = {
            self.RISK_CRITICAL: 0,
            self.RISK_HIGH: 1,
            self.RISK_MEDIUM: 2,
            self.RISK_LOW: 3,
        }
        summaries.sort(key=lambda s: (risk_order.get(s.risk_level, 4), -s.anomaly_rate))
        
        return summaries
    
    def _create_user_summary(self, user_id: str, results: list[AnomalyResult]) -> UserSummary:
        """Create a summary for a single user."""
        scores = [r.anomaly_score for r in results]
        anomalies = [r for r in results if r.is_anomaly]
        
        timestamps = [r.timestamp for r in results if r.timestamp]
        
        summary = UserSummary(
            user_id=user_id,
            total_events=len(results),
            anomaly_count=len(anomalies),
            anomaly_rate=len(anomalies) / len(results) if results else 0.0,
            mean_score=float(np.mean(scores)),
            min_score=float(np.min(scores)),
            max_score=float(np.max(scores)),
            score_std=float(np.std(scores)),
            first_event=min(timestamps) if timestamps else None,
            last_event=max(timestamps) if timestamps else None,
            anomalous_event_indices=[r.event_index for r in anomalies],
        )
        
        # Assess risk level
        summary.risk_level = self._assess_risk(summary)
        
        return summary
    
    def _assess_risk(self, summary: UserSummary) -> str:
        # Critical: High anomaly rate or very low scores
        if summary.anomaly_rate > self.CRITICAL_RATE_THRESHOLD or summary.min_score < self.CRITICAL_SCORE_THRESHOLD:
            return self.RISK_CRITICAL
        
        # High: Moderate anomaly rate or consistently low scores
        if summary.anomaly_rate > self.HIGH_RATE_THRESHOLD or summary.mean_score < self.HIGH_SCORE_THRESHOLD:
            return self.RISK_HIGH
        
        # Medium: Some anomalies but not alarming
        if summary.anomaly_rate > self.MEDIUM_RATE_THRESHOLD or summary.anomaly_count > 0:
            return self.RISK_MEDIUM
        
        # Low: Normal behavior
        return self.RISK_LOW
    
    def _calculate_user_baselines(self, results: list[AnomalyResult]) -> None:
        """Calculate per-user baseline scores for context."""
        # Group by user
        user_scores: dict[str, list[float]] = defaultdict(list)
        for result in results:
            user_scores[result.user_id].append(result.anomaly_score)
        
        # Calculate baseline (mean score) for each user
        user_baselines = {
            user_id: np.mean(scores) 
            for user_id, scores in user_scores.items()
        }
        
        # Assign baseline to each result
        for result in results:
            result.user_baseline_score = user_baselines.get(result.user_id, 0.0)
    
    def get_score_distribution(self, results: list[AnomalyResult]) -> dict[str, Any]:
        """
        Get distribution statistics for anomaly scores.
        
        Args:
            results: List of AnomalyResult objects
            
        Returns:
            Dictionary with distribution statistics
        """
        scores = [r.anomaly_score for r in results]
        
        return {
            "count": len(scores),
            "mean": float(np.mean(scores)),
            "std": float(np.std(scores)),
            "min": float(np.min(scores)),
            "max": float(np.max(scores)),
            "median": float(np.median(scores)),
            "percentiles": {
                "1": float(np.percentile(scores, 1)),
                "5": float(np.percentile(scores, 5)),
                "10": float(np.percentile(scores, 10)),
                "25": float(np.percentile(scores, 25)),
                "50": float(np.percentile(scores, 50)),
                "75": float(np.percentile(scores, 75)),
                "90": float(np.percentile(scores, 90)),
                "95": float(np.percentile(scores, 95)),
                "99": float(np.percentile(scores, 99)),
            },
            "threshold": self.threshold,
            "anomaly_count": sum(r.is_anomaly for r in results),
            "anomaly_rate": sum(r.is_anomaly for r in results) / len(results) if results else 0.0,
        }

    def _attach_research_context(
        self,
        result: AnomalyResult,
        feature_row: pd.Series,
    ) -> None:
        research_columns = [
            "identity_sequence_score",
            "identity_relationship_score",
            "identity_fusion_score",
            "identity_takeover_score",
        ]
        result.research_signals = {
            column: float(feature_row[column])
            for column in research_columns
            if column in feature_row.index
        }

        raw_reasons = feature_row.get("identity_reasons", [])
        if isinstance(raw_reasons, list):
            result.research_reasons = [str(reason) for reason in raw_reasons]
        elif isinstance(raw_reasons, str) and raw_reasons:
            result.research_reasons = [chunk.strip() for chunk in raw_reasons.split("|") if chunk.strip()]

    def _identity_floor_hit(self, feature_row: pd.Series) -> bool:
        if self.identity_hard_floor is None:
            return False
        identity_score = feature_row.get(self.identity_hard_floor_column)
        if identity_score is None:
            return False
        try:
            primary_hit = float(identity_score) >= float(self.identity_hard_floor)
        except (TypeError, ValueError):
            return False
        if not primary_hit:
            return False
        if self.identity_hard_floor_support_column is None:
            return True
        support_score = feature_row.get(self.identity_hard_floor_support_column)
        if support_score is None:
            return False
        try:
            return float(support_score) >= float(self.identity_hard_floor_support_threshold)
        except (TypeError, ValueError):
            return False

"""
Feature engineering module for behavioral anomaly detection.

Extracts behavioral signals from authentication events including:
- Time-of-day patterns (cyclical encoding)
- Login velocity and frequency
- Geographic consistency and impossible travel
- ASN switching
- Device variability
- Failed-then-success patterns
- Session duration deviation
- Peer-group deviation (v0.2)
- Entropy features (v0.2)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Any
import logging
import math
from collections import defaultdict, Counter

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

from chimera.data_loader import AuthEvent
from chimera.threat_intel import ThreatIntel

logger = logging.getLogger(__name__)


@dataclass
class UserBehaviorProfile:
    """
    Behavioral profile for a single user.

    Stores historical patterns used to detect deviations.
    """
    user_id: str

    # Temporal patterns
    typical_hours: list[int] = field(default_factory=list)
    typical_days: list[int] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Network patterns
    known_ips: set[str] = field(default_factory=set)
    known_asns: set[str] = field(default_factory=set)
    known_countries: set[str] = field(default_factory=set)

    # Device patterns
    known_user_agents: set[str] = field(default_factory=set)
    known_devices: set[str] = field(default_factory=set)

    # Session patterns
    typical_session_duration: Optional[float] = None
    session_durations: list[float] = field(default_factory=list)

    # Authentication patterns
    typical_auth_methods: set[str] = field(default_factory=set)
    failure_rate: float = 0.0
    total_events: int = 0
    failure_count: int = 0

    # Velocity tracking
    event_times: list[datetime] = field(default_factory=list)

    def update(self, event: AuthEvent) -> None:
        """Update profile with a new event."""
        self.total_events += 1
        self.event_times.append(event.timestamp)

        # Keep only last 1000 event times for memory efficiency
        if len(self.event_times) > 1000:
            self.event_times = self.event_times[-1000:]

        # Update temporal patterns
        self.typical_hours.append(event.hour_of_day)
        self.typical_days.append(event.day_of_week)

        # Keep only recent patterns
        if len(self.typical_hours) > 100:
            self.typical_hours = self.typical_hours[-100:]
            self.typical_days = self.typical_days[-100:]

        # Update first/last seen
        if self.first_seen is None or event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if self.last_seen is None or event.timestamp > self.last_seen:
            self.last_seen = event.timestamp

        # Update network patterns
        if event.ip_address:
            self.known_ips.add(event.ip_address)
        if event.asn:
            self.known_asns.add(event.asn)
        if event.country_code:
            self.known_countries.add(event.country_code)

        # Update device patterns
        if event.user_agent:
            self.known_user_agents.add(event.user_agent)
        if event.device_fingerprint:
            self.known_devices.add(event.device_fingerprint)

        # Update session patterns
        if event.session_duration_seconds is not None:
            self.session_durations.append(event.session_duration_seconds)
            if len(self.session_durations) > 100:
                self.session_durations = self.session_durations[-100:]
            self.typical_session_duration = float(np.median(self.session_durations))

        # Update auth patterns
        if event.auth_method:
            self.typical_auth_methods.add(event.auth_method)

        if event.is_failure:
            self.failure_count += 1

        self.failure_rate = self.failure_count / self.total_events


# ── Shannon entropy helper ───────────────────────────────────────


def _shannon_entropy(values: list[str]) -> float:
    """Compute Shannon entropy of a list of categorical values."""
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class FeatureEngineer:
    """
    Feature engineering for behavioral anomaly detection.

    Extracts features from authentication events for use with
    unsupervised learning models.
    """

    # Feature groups
    TEMPORAL_FEATURES = [
        "hour_sin", "hour_cos",  # Cyclical hour encoding
        "day_of_week", "is_weekend",
        "is_typical_hour", "is_typical_day",
    ]

    VELOCITY_FEATURES = [
        "events_last_hour",
        "events_last_day",
        "time_since_last_event",
        "avg_inter_event_time",
    ]

    GEOGRAPHIC_FEATURES = [
        "is_known_ip", "is_known_country", "is_known_asn",
        "unique_ips_24h", "unique_countries_24h", "unique_asns_24h",
        "ip_change_frequency",
        "is_threat_ip", "is_threat_asn",
    ]

    DEVICE_FEATURES = [
        "is_known_device", "is_known_user_agent",
        "unique_devices_24h", "unique_user_agents_24h",
    ]

    SESSION_FEATURES = [
        "session_duration_zscore",
        "session_duration_ratio",
    ]

    AUTH_FEATURES = [
        "is_failure", "failure_streak",
        "failed_then_success",
        "is_unusual_auth_method",
    ]

    # v0.2 features
    ENTROPY_FEATURES = [
        "ip_entropy", "device_entropy", "country_entropy",
    ]

    PEER_GROUP_FEATURES = [
        "peer_hour_deviation", "peer_velocity_deviation",
    ]

    TRAVEL_FEATURES = [
        "impossible_travel_flag",
    ]

    def __init__(
        self,
        max_history_days: int = 30,
        enable_entropy: bool = True,
        enable_peer_group: bool = True,
        enable_impossible_travel: bool = True,
        threat_feed_path: Optional[str] = None,
    ):
        self.max_history_days = max_history_days
        self.enable_entropy = enable_entropy
        self.enable_peer_group = enable_peer_group
        self.enable_impossible_travel = enable_impossible_travel
        self.threat_intel = ThreatIntel(feed_path=threat_feed_path)
        self.user_profiles: dict[str, UserBehaviorProfile] = {}
        self.scaler = StandardScaler()
        self.label_encoders: dict[str, LabelEncoder] = {}
        self.is_fitted = False

        # Peer-group stats (computed during fit)
        self._global_hour_mean: float = 12.0
        self._global_hour_std: float = 6.0
        self._global_velocity_mean: float = 5.0
        self._global_velocity_std: float = 3.0

        self._feature_names: Optional[list[str]] = None

    def fit(self, events: list[AuthEvent]) -> "FeatureEngineer":
        """Build user profiles from historical events."""
        logger.info(f"Building profiles from {len(events)} events")

        sorted_events = sorted(events, key=lambda e: e.timestamp)

        for event in sorted_events:
            if event.user_id not in self.user_profiles:
                self.user_profiles[event.user_id] = UserBehaviorProfile(
                    user_id=event.user_id
                )
            self.user_profiles[event.user_id].update(event)

        # Compute global peer-group statistics
        all_hours = [e.hour_of_day for e in sorted_events]
        if all_hours:
            self._global_hour_mean = float(np.mean(all_hours))
            self._global_hour_std = max(float(np.std(all_hours)), 1.0)

        user_event_counts = defaultdict(int)
        for e in sorted_events:
            user_event_counts[e.user_id] += 1
        if user_event_counts:
            counts = list(user_event_counts.values())
            self._global_velocity_mean = float(np.mean(counts))
            self._global_velocity_std = max(float(np.std(counts)), 1.0)

        logger.info(f"Built profiles for {len(self.user_profiles)} users")
        return self

    def transform(self, events: list[AuthEvent]) -> pd.DataFrame:
        """Transform events into feature vectors."""
        features_list = []

        for event in events:
            features = self._extract_features(event)
            features_list.append(features)

        df = pd.DataFrame(features_list)

        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)

        return df

    def fit_transform(self, events: list[AuthEvent]) -> pd.DataFrame:
        """Fit profiles and transform events in one step."""
        return self.fit(events).transform(events)

    def _extract_features(self, event: AuthEvent) -> dict[str, Any]:
        """Extract all features for a single event."""
        profile = self.user_profiles.get(event.user_id)

        features: dict[str, Any] = {
            "user_id": event.user_id,
            "event_timestamp": event.timestamp,
            "event_type": event.event_type,
        }

        features.update(self._extract_temporal_features(event, profile))
        features.update(self._extract_velocity_features(event, profile))
        features.update(self._extract_geographic_features(event, profile))
        features.update(self._extract_device_features(event, profile))
        features.update(self._extract_session_features(event, profile))
        features.update(self._extract_auth_features(event, profile))

        # v0.2 feature groups
        if self.enable_entropy:
            features.update(self._extract_entropy_features(event, profile))
        if self.enable_peer_group:
            features.update(self._extract_peer_group_features(event, profile))
        if self.enable_impossible_travel:
            features.update(self._extract_travel_features(event, profile))

        return features

    # ── Core feature extractors (unchanged from v0.1) ────────────

    def _extract_temporal_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        hour = event.hour_of_day
        day = event.day_of_week

        hour_sin = np.sin(2 * np.pi * hour / 24)
        hour_cos = np.cos(2 * np.pi * hour / 24)

        features = {
            "hour_sin": hour_sin,
            "hour_cos": hour_cos,
            "day_of_week": day,
            "is_weekend": 1.0 if event.is_weekend else 0.0,
        }

        if profile and profile.typical_hours:
            is_typical_hour = any(
                abs(hour - h) <= 2 or abs(hour - h) >= 22
                for h in profile.typical_hours[-20:]
            )
            is_typical_day = day in profile.typical_days[-20:]
        else:
            is_typical_hour = True
            is_typical_day = True

        features["is_typical_hour"] = 1.0 if is_typical_hour else 0.0
        features["is_typical_day"] = 1.0 if is_typical_day else 0.0

        return features

    def _extract_velocity_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        features = {
            "events_last_hour": 0.0,
            "events_last_day": 0.0,
            "time_since_last_event": 86400.0,
            "avg_inter_event_time": 86400.0,
        }

        if not profile or not profile.event_times:
            return features

        now = event.timestamp
        one_hour_ago = now - timedelta(hours=1)
        one_day_ago = now - timedelta(days=1)

        events_last_hour = sum(1 for t in profile.event_times if one_hour_ago <= t < now)
        events_last_day = sum(1 for t in profile.event_times if one_day_ago <= t < now)

        last_event_time = profile.event_times[-1] if profile.event_times else None
        if last_event_time and last_event_time < now:
            time_since_last = (now - last_event_time).total_seconds()
        else:
            time_since_last = 86400.0

        recent_times = [t for t in profile.event_times if one_day_ago <= t < now]
        if len(recent_times) >= 2:
            intervals = [
                (recent_times[i] - recent_times[i - 1]).total_seconds()
                for i in range(1, len(recent_times))
            ]
            avg_interval = float(np.mean(intervals)) if intervals else 86400.0
        else:
            avg_interval = 86400.0

        features.update({
            "events_last_hour": float(events_last_hour),
            "events_last_day": float(events_last_day),
            "time_since_last_event": min(time_since_last, 86400.0),
            "avg_inter_event_time": min(avg_interval, 86400.0),
        })

        return features

    def _extract_geographic_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        features = {
            "is_known_ip": 1.0,
            "is_known_country": 1.0,
            "is_known_asn": 1.0,
            "unique_ips_24h": 1.0,
            "unique_countries_24h": 1.0,
            "unique_asns_24h": 1.0,
            "ip_change_frequency": 0.0,
            "is_threat_ip": 0.0,
            "is_threat_asn": 0.0,
        }

        if not profile:
            return features

        is_known_ip = event.ip_address in profile.known_ips if event.ip_address else True
        is_known_country = event.country_code in profile.known_countries if event.country_code else True
        is_known_asn = event.asn in profile.known_asns if event.asn else True

        unique_ips = len(profile.known_ips) if profile.known_ips else 1
        unique_countries = len(profile.known_countries) if profile.known_countries else 1
        unique_asns = len(profile.known_asns) if profile.known_asns else 1

        ip_change_freq = unique_ips / max(profile.total_events, 1)

        features.update({
            "is_known_ip": 1.0 if is_known_ip else 0.0,
            "is_known_country": 1.0 if is_known_country else 0.0,
            "is_known_asn": 1.0 if is_known_asn else 0.0,
            "unique_ips_24h": float(unique_ips),
            "unique_countries_24h": float(unique_countries),
            "unique_asns_24h": float(unique_asns),
            "ip_change_frequency": ip_change_freq,
            "is_threat_ip": self.threat_intel.check_ip(event.ip_address) if event.ip_address else 0.0,
            "is_threat_asn": self.threat_intel.check_asn(event.asn) if event.asn else 0.0,
        })

        return features

    def _extract_device_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        features = {
            "is_known_device": 1.0,
            "is_known_user_agent": 1.0,
            "unique_devices_24h": 1.0,
            "unique_user_agents_24h": 1.0,
        }

        if not profile:
            return features

        is_known_device = event.device_fingerprint in profile.known_devices if event.device_fingerprint else True
        is_known_ua = event.user_agent in profile.known_user_agents if event.user_agent else True

        unique_devices = len(profile.known_devices) if profile.known_devices else 1
        unique_uas = len(profile.known_user_agents) if profile.known_user_agents else 1

        features.update({
            "is_known_device": 1.0 if is_known_device else 0.0,
            "is_known_user_agent": 1.0 if is_known_ua else 0.0,
            "unique_devices_24h": float(unique_devices),
            "unique_user_agents_24h": float(unique_uas),
        })

        return features

    def _extract_session_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        features = {
            "session_duration_zscore": 0.0,
            "session_duration_ratio": 1.0,
        }

        if not profile or event.session_duration_seconds is None:
            return features

        durations = profile.session_durations
        current_duration = event.session_duration_seconds

        if len(durations) >= 3 and profile.typical_session_duration:
            mean_duration = float(np.mean(durations))
            std_duration = float(np.std(durations))

            if std_duration > 0:
                zscore = (current_duration - mean_duration) / std_duration
            else:
                zscore = 0.0

            ratio = current_duration / max(profile.typical_session_duration, 1)

            features.update({
                "session_duration_zscore": zscore,
                "session_duration_ratio": ratio,
            })

        return features

    def _extract_auth_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        features = {
            "is_failure": 1.0 if event.is_failure else 0.0,
            "failure_streak": 0.0,
            "failed_then_success": 0.0,
            "is_unusual_auth_method": 0.0,
        }

        if not profile:
            return features

        recent_failure_rate = profile.failure_rate
        failure_streak = recent_failure_rate * 5

        failed_then_success = 0.0
        if event.success and recent_failure_rate > 0.3:
            failed_then_success = 1.0

        is_unusual_method = False
        if event.auth_method and profile.typical_auth_methods:
            is_unusual_method = event.auth_method not in profile.typical_auth_methods

        features.update({
            "failure_streak": failure_streak,
            "failed_then_success": failed_then_success,
            "is_unusual_auth_method": 1.0 if is_unusual_method else 0.0,
        })

        return features

    # ── v0.2 feature extractors ──────────────────────────────────

    def _extract_entropy_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        """
        Shannon entropy of the user's IP, device, and country distributions.

        Higher entropy = more varied behavior = potentially suspicious.
        """
        if not profile:
            return {"ip_entropy": 0.0, "device_entropy": 0.0, "country_entropy": 0.0}

        ip_entropy = _shannon_entropy(list(profile.known_ips))
        device_entropy = _shannon_entropy(
            list(profile.known_devices) or list(profile.known_user_agents)
        )
        country_entropy = _shannon_entropy(list(profile.known_countries))

        return {
            "ip_entropy": ip_entropy,
            "device_entropy": device_entropy,
            "country_entropy": country_entropy,
        }

    def _extract_peer_group_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        """
        Compare the user's behavior against the global peer-group mean.

        Large deviations indicate unusual behavior relative to peers.
        """
        hour = event.hour_of_day
        peer_hour_dev = abs(hour - self._global_hour_mean) / self._global_hour_std

        if profile:
            user_velocity = profile.total_events
            peer_vel_dev = abs(user_velocity - self._global_velocity_mean) / self._global_velocity_std
        else:
            peer_vel_dev = 0.0

        return {
            "peer_hour_deviation": peer_hour_dev,
            "peer_velocity_deviation": peer_vel_dev,
        }

    def _extract_travel_features(
        self, event: AuthEvent, profile: Optional[UserBehaviorProfile]
    ) -> dict[str, Any]:
        """
        Flag events where the user appears to have changed country
        faster than physically possible (heuristic: < 1 hour).
        """
        if (
            not profile
            or not event.country_code
            or not profile.known_countries
            or not profile.event_times
        ):
            return {"impossible_travel_flag": 0.0}

        # Check the most recent event
        if len(profile.event_times) < 2:
            return {"impossible_travel_flag": 0.0}

        last_time = profile.event_times[-1]
        time_diff = (event.timestamp - last_time).total_seconds()

        # If country changed and time gap is < 1 hour, flag
        if (
            event.country_code not in profile.known_countries
            and 0 < time_diff < 3600
        ):
            return {"impossible_travel_flag": 1.0}

        return {"impossible_travel_flag": 0.0}

    # ── Feature name helpers ─────────────────────────────────────

    def get_feature_names(self) -> list[str]:
        """Get list of feature names (excluding metadata)."""
        if self._feature_names is None:
            all_features = (
                self.TEMPORAL_FEATURES
                + self.VELOCITY_FEATURES
                + self.GEOGRAPHIC_FEATURES
                + self.DEVICE_FEATURES
                + self.SESSION_FEATURES
                + self.AUTH_FEATURES
            )
            if self.enable_entropy:
                all_features += self.ENTROPY_FEATURES
            if self.enable_peer_group:
                all_features += self.PEER_GROUP_FEATURES
            if self.enable_impossible_travel:
                all_features += self.TRAVEL_FEATURES
            self._feature_names = all_features
        return self._feature_names

    def get_numeric_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """Extract numeric features for model input."""
        feature_names = self.get_feature_names()
        available_features = [f for f in feature_names if f in features_df.columns]
        return features_df[available_features].astype(float)

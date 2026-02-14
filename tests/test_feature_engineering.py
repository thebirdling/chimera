"""Tests for feature_engineering module."""

from datetime import datetime, timedelta

import pytest
import numpy as np

from chimera.data_loader import AuthEvent
from chimera.feature_engineering import FeatureEngineer, UserBehaviorProfile


class TestUserBehaviorProfile:
    """Tests for UserBehaviorProfile."""
    
    def test_update(self):
        profile = UserBehaviorProfile(user_id="alice")
        
        event = AuthEvent(
            timestamp=datetime(2024, 1, 15, 9, 30, 0),
            user_id="alice",
            event_type="login",
            ip_address="192.168.1.1",
            country_code="US",
        )
        
        profile.update(event)
        
        assert profile.total_events == 1
        assert "192.168.1.1" in profile.known_ips
        assert "US" in profile.known_countries
    
    def test_multiple_updates(self):
        profile = UserBehaviorProfile(user_id="alice")
        
        base_time = datetime(2024, 1, 15, 9, 0, 0)
        
        for i in range(5):
            event = AuthEvent(
                timestamp=base_time + timedelta(hours=i),
                user_id="alice",
                event_type="login",
                ip_address=f"192.168.1.{i+1}",
            )
            profile.update(event)
        
        assert profile.total_events == 5
        assert len(profile.known_ips) == 5


class TestFeatureEngineer:
    """Tests for FeatureEngineer."""
    
    def test_extract_temporal_features(self):
        engineer = FeatureEngineer()
        
        event = AuthEvent(
            timestamp=datetime(2024, 1, 15, 14, 30, 0),  # Monday 2:30 PM
            user_id="alice",
            event_type="login",
        )
        
        features = engineer._extract_temporal_features(event, None)
        
        assert "hour_sin" in features
        assert "hour_cos" in features
        assert features["day_of_week"] == 0  # Monday
        assert features["is_weekend"] == 0.0
    
    def test_extract_velocity_features(self):
        engineer = FeatureEngineer()
        
        # Create a profile with some history
        profile = UserBehaviorProfile(user_id="alice")
        base_time = datetime(2024, 1, 15, 9, 0, 0)
        
        for i in range(5):
            event = AuthEvent(
                timestamp=base_time + timedelta(minutes=i*10),
                user_id="alice",
                event_type="login",
            )
            profile.update(event)
        
        current_event = AuthEvent(
            timestamp=base_time + timedelta(hours=1),
            user_id="alice",
            event_type="login",
        )
        
        features = engineer._extract_velocity_features(current_event, profile)
        
        assert "events_last_hour" in features
        assert "time_since_last_event" in features
    
    def test_extract_geographic_features(self):
        engineer = FeatureEngineer()
        
        profile = UserBehaviorProfile(user_id="alice")
        profile.known_ips.add("192.168.1.1")
        profile.known_countries.add("US")
        
        # Known IP
        known_event = AuthEvent(
            timestamp=datetime.now(),
            user_id="alice",
            event_type="login",
            ip_address="192.168.1.1",
            country_code="US",
        )
        
        features = engineer._extract_geographic_features(known_event, profile)
        assert features["is_known_ip"] == 1.0
        assert features["is_known_country"] == 1.0
        
        # Unknown IP
        unknown_event = AuthEvent(
            timestamp=datetime.now(),
            user_id="alice",
            event_type="login",
            ip_address="10.0.0.1",
            country_code="RU",
        )
        
        features = engineer._extract_geographic_features(unknown_event, profile)
        assert features["is_known_ip"] == 0.0
        assert features["is_known_country"] == 0.0
    
    def test_fit_transform(self):
        engineer = FeatureEngineer()
        
        events = [
            AuthEvent(
                timestamp=datetime(2024, 1, 15, 9, 0, 0) + timedelta(hours=i),
                user_id="alice",
                event_type="login",
                ip_address="192.168.1.1",
            )
            for i in range(10)
        ]
        
        features_df = engineer.fit_transform(events)
        
        assert len(features_df) == 10
        assert "hour_sin" in features_df.columns
        assert "hour_cos" in features_df.columns
        assert "is_known_ip" in features_df.columns
    
    def test_get_numeric_features(self):
        engineer = FeatureEngineer()
        
        events = [
            AuthEvent(
                timestamp=datetime(2024, 1, 15, 9, 0, 0),
                user_id="alice",
                event_type="login",
            )
            for _ in range(5)
        ]
        
        features_df = engineer.fit_transform(events)
        numeric_df = engineer.get_numeric_features(features_df)
        
        # Should only contain numeric columns
        assert all(np.issubdtype(dtype, np.number) for dtype in numeric_df.dtypes)

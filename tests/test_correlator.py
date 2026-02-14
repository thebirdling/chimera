"""
Tests for the correlation engine.
"""

import pytest
from datetime import datetime

from chimera.data_loader import AuthEvent
from chimera.correlator import EventCorrelator


def _make_event(
    user_id: str = "user_001",
    timestamp: str = "2025-01-15T10:00:00",
    ip_address: str = "10.0.0.1",
    event_type: str = "login_success",
    **kwargs,
) -> AuthEvent:
    return AuthEvent(
        timestamp=datetime.fromisoformat(timestamp),
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        success=True,
        **kwargs,
    )


class TestEventCorrelator:
    def test_correlate_by_ip(self):
        """Multiple users from the same IP should form a cluster."""
        events = [
            _make_event(user_id=f"user_{i}", ip_address="192.168.1.100", timestamp=f"2025-01-15T10:0{i}:00")
            for i in range(5)
        ]

        correlator = EventCorrelator(min_users_for_cluster=3)
        clusters = correlator.correlate_by_ip(events)

        assert len(clusters) >= 1
        assert clusters[0].correlation_type == "shared_ip"
        assert len(clusters[0].users) >= 3

    def test_correlate_by_timing(self):
        """Burst of events from many users should form a cluster."""
        events = [
            _make_event(
                user_id=f"user_{i}",
                ip_address=f"10.0.0.{i}",
                timestamp=f"2025-01-15T10:00:0{i}",
            )
            for i in range(5)
        ]

        correlator = EventCorrelator(burst_window_minutes=5, min_users_for_cluster=3)
        clusters = correlator.correlate_by_timing(events)

        assert len(clusters) >= 1
        assert clusters[0].correlation_type == "timing_burst"

    def test_no_cluster_below_threshold(self):
        """Fewer users than threshold should produce no clusters."""
        events = [
            _make_event(user_id=f"user_{i}", ip_address="192.168.1.100", timestamp=f"2025-01-15T10:0{i}:00")
            for i in range(2)
        ]

        correlator = EventCorrelator(min_users_for_cluster=3)
        clusters = correlator.correlate_by_ip(events)
        assert len(clusters) == 0

    def test_full_correlate(self):
        """Full correlate should run all strategies without error."""
        events = [
            _make_event(user_id=f"user_{i}", timestamp=f"2025-01-15T10:0{i}:00")
            for i in range(5)
        ]

        correlator = EventCorrelator()
        clusters = correlator.correlate(events)
        # Should at least run without error
        assert isinstance(clusters, list)

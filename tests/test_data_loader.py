"""Tests for data_loader module."""

import json
import csv
from datetime import datetime
from pathlib import Path
import tempfile

import pytest

from chimera.data_loader import AuthLogLoader, AuthEvent


class TestAuthEvent:
    """Tests for AuthEvent dataclass."""
    
    def test_basic_creation(self):
        event = AuthEvent(
            timestamp=datetime(2024, 1, 15, 9, 30, 0),
            user_id="alice@example.com",
            event_type="login",
        )
        assert event.user_id == "alice@example.com"
        assert event.event_type == "login"
        assert event.hour_of_day == 9
        assert event.day_of_week == 0  # Monday
    
    def test_is_failure(self):
        failed = AuthEvent(
            timestamp=datetime.now(),
            user_id="user",
            event_type="failed_login",
        )
        assert failed.is_failure is True
        
        success = AuthEvent(
            timestamp=datetime.now(),
            user_id="user",
            event_type="login",
            success=True,
        )
        assert success.is_failure is False
    
    def test_to_dict(self):
        event = AuthEvent(
            timestamp=datetime(2024, 1, 15, 9, 30, 0),
            user_id="alice@example.com",
            event_type="login",
            ip_address="192.168.1.1",
        )
        d = event.to_dict()
        assert d["user_id"] == "alice@example.com"
        assert d["ip_address"] == "192.168.1.1"


class TestAuthLogLoader:
    """Tests for AuthLogLoader."""
    
    def test_load_csv(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "user_id", "event_type", "ip_address"])
            writer.writerow(["2024-01-15T09:30:00", "alice", "login", "192.168.1.1"])
            writer.writerow(["2024-01-15T10:00:00", "bob", "logout", "192.168.1.2"])
            temp_path = f.name
        
        try:
            loader = AuthLogLoader()
            events = loader.load(temp_path)
            
            assert len(events) == 2
            assert events[0].user_id == "alice"
            assert events[0].event_type == "login"
            assert events[1].user_id == "bob"
        finally:
            Path(temp_path).unlink()
    
    def test_load_json(self):
        data = [
            {"timestamp": "2024-01-15T09:30:00", "user_id": "alice", "event_type": "login"},
            {"timestamp": "2024-01-15T10:00:00", "user_id": "bob", "event_type": "logout"},
        ]
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            loader = AuthLogLoader()
            events = loader.load(temp_path)
            
            assert len(events) == 2
            assert events[0].user_id == "alice"
        finally:
            Path(temp_path).unlink()
    
    def test_field_detection(self):
        # Test with alternative field names
        data = [
            {"time": "2024-01-15T09:30:00", "username": "alice", "action": "login"},
        ]
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name
        
        try:
            loader = AuthLogLoader()
            events = loader.load(temp_path)
            
            assert len(events) == 1
            assert events[0].user_id == "alice"
            assert events[0].event_type == "login"
        finally:
            Path(temp_path).unlink()
    
    def test_validate_events(self):
        events = [
            AuthEvent(timestamp=datetime.now(), user_id="alice", event_type="login"),
            AuthEvent(timestamp=datetime.now(), user_id="bob", event_type="login"),
            AuthEvent(timestamp=datetime.now(), user_id="alice", event_type="logout"),
        ]
        
        loader = AuthLogLoader()
        stats = loader.validate_events(events)
        
        assert stats["total_events"] == 3
        assert stats["unique_users"] == 2
        assert "event_types" in stats

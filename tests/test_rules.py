"""
Tests for the rule engine and built-in rules.
"""

import pytest
from datetime import datetime

from chimera.data_loader import AuthEvent
from chimera.rules.engine import RuleEngine, RuleDefinition


def _make_event(
    user_id: str = "user_001",
    timestamp: str = "2025-01-15T10:00:00",
    event_type: str = "login_success",
    ip_address: str = "10.0.0.1",
    country_code: str = "US",
    success: bool = True,
    mfa_used: bool = False,
    session_id: str = "sess1",
    **kwargs,
) -> AuthEvent:
    return AuthEvent(
        timestamp=datetime.fromisoformat(timestamp),
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        country_code=country_code,
        success=success,
        mfa_used=mfa_used,
        session_id=session_id,
        **kwargs,
    )


class TestRuleEngine:
    def test_load_builtins(self):
        engine = RuleEngine()
        engine.load_builtin_rules()
        rules = engine.list_rules()
        assert len(rules) == 8

    def test_rule_ids(self):
        engine = RuleEngine()
        engine.load_builtin_rules()
        rule_ids = {r.id for r in engine.list_rules()}
        expected = {
            "brute_force", "impossible_travel", "credential_stuffing",
            "off_hours_login", "dormant_account", "new_device_new_location",
            "mfa_bypass", "session_hijack",
        }
        assert rule_ids == expected


class TestBruteForceRule:
    def test_detects_brute_force(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(
                user_id="victim",
                timestamp=f"2025-01-15T10:{i:02d}:00",
                event_type="failed_login",
                success=False,
            )
            for i in range(7)
        ]

        matches = engine.evaluate(events)
        brute = [m for m in matches if m.rule_id == "brute_force"]
        assert len(brute) >= 1
        assert brute[0].severity == "high"

    def test_no_false_positive(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(
                user_id="normal_user",
                timestamp=f"2025-01-15T{10+i}:00:00",
                event_type="login_success",
            )
            for i in range(5)
        ]

        matches = engine.evaluate(events)
        brute = [m for m in matches if m.rule_id == "brute_force"]
        assert len(brute) == 0


class TestImpossibleTravelRule:
    def test_detects_impossible_travel(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(user_id="traveler", timestamp="2025-01-15T10:00:00", country_code="US"),
            _make_event(user_id="traveler", timestamp="2025-01-15T10:15:00", country_code="JP"),
        ]

        matches = engine.evaluate(events)
        travel = [m for m in matches if m.rule_id == "impossible_travel"]
        assert len(travel) >= 1
        assert travel[0].severity == "critical"


class TestCredentialStuffingRule:
    def test_detects_stuffing(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(
                user_id=f"victim_{i}",
                timestamp=f"2025-01-15T10:0{i}:00",
                event_type="failed_login",
                ip_address="192.168.1.100",
                success=False,
            )
            for i in range(5)
        ]

        matches = engine.evaluate(events)
        stuffing = [m for m in matches if m.rule_id == "credential_stuffing"]
        assert len(stuffing) >= 1


class TestOffHoursRule:
    def test_detects_off_hours(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(timestamp="2025-01-15T03:00:00"),
        ]

        matches = engine.evaluate(events)
        off_hours = [m for m in matches if m.rule_id == "off_hours_login"]
        assert len(off_hours) == 1


class TestSessionHijackRule:
    def test_detects_ip_change(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(session_id="sess_x", ip_address="10.0.0.1", timestamp="2025-01-15T10:00:00"),
            _make_event(session_id="sess_x", ip_address="192.168.1.1", timestamp="2025-01-15T10:05:00"),
        ]

        matches = engine.evaluate(events)
        hijack = [m for m in matches if m.rule_id == "session_hijack"]
        assert len(hijack) >= 1
        assert hijack[0].severity == "critical"

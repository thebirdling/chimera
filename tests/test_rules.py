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
    user_agent: str = "Mozilla/5.0",
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
        user_agent=user_agent,
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
        assert len(rules) == 11

    def test_rule_ids(self):
        engine = RuleEngine()
        engine.load_builtin_rules()
        rule_ids = {r.id for r in engine.list_rules()}
        expected = {
            "brute_force", "impossible_travel", "credential_stuffing",
            "password_spraying", "low_and_slow_campaign",
            "off_hours_login", "dormant_account", "new_device_new_location",
            "mfa_bypass", "session_hijack", "shared_infrastructure_burst",
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

        events = []
        for i in range(6):
            events.append(
                _make_event(
                    user_id=f"victim_{i % 4}",
                    timestamp=f"2025-01-15T10:0{i}:00",
                    event_type="failed_login",
                    ip_address="192.168.1.100",
                    success=False,
                )
            )

        matches = engine.evaluate(events)
        stuffing = [m for m in matches if m.rule_id == "credential_stuffing"]
        assert len(stuffing) >= 1
        assert stuffing[0].details["failed_attempt_count"] >= 6


class TestPasswordSprayingRule:
    def test_detects_password_spraying(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(
                user_id=f"victim_{i}",
                timestamp=f"2025-01-15T10:{i:02d}:00",
                event_type="failed_login",
                ip_address="203.0.113.10",
                success=False,
            )
            for i in range(5)
        ]

        matches = engine.evaluate(events)
        spraying = [m for m in matches if m.rule_id == "password_spraying"]
        assert len(spraying) >= 1
        assert spraying[0].details["max_attempts_per_user"] <= 2


class TestLowAndSlowCampaignRule:
    def test_detects_low_and_slow_campaign(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        minute_offsets = [0, 25, 55, 90, 125]
        events = [
            _make_event(
                user_id=f"victim_{i}",
                timestamp=f"2025-01-15T{10 + (minute_offsets[i] // 60):02d}:{minute_offsets[i] % 60:02d}:00",
                event_type="failed_login",
                ip_address="198.51.100.22",
                success=False,
            )
            for i in range(len(minute_offsets))
        ]

        matches = engine.evaluate(events)
        campaign = [m for m in matches if m.rule_id == "low_and_slow_campaign"]
        assert len(campaign) >= 1
        assert campaign[0].details["span_minutes"] >= 30.0


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

    def test_detects_user_agent_change(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(
                session_id="sess_ua",
                ip_address="10.0.0.1",
                user_agent="Mozilla/5.0",
                timestamp="2025-01-15T10:00:00",
            ),
            _make_event(
                session_id="sess_ua",
                ip_address="10.0.0.1",
                user_agent="python-requests/2.31",
                timestamp="2025-01-15T10:03:00",
            ),
        ]

        matches = engine.evaluate(events)
        hijack = [m for m in matches if m.rule_id == "session_hijack"]
        assert len(hijack) >= 1
        assert hijack[0].details["new_user_agent"] == "python-requests/2.31"


class TestSharedInfrastructureBurstRule:
    def test_detects_multi_user_same_ip_same_asn_burst(self):
        engine = RuleEngine()
        engine.load_builtin_rules()

        events = [
            _make_event(
                user_id=f"user_{i}",
                timestamp=f"2025-01-15T10:0{i}:00",
                ip_address="192.168.1.100",
                asn="64512",
                success=True,
            )
            for i in range(4)
        ]

        matches = engine.evaluate(events)
        burst = [m for m in matches if m.rule_id == "shared_infrastructure_burst"]
        assert len(burst) >= 1

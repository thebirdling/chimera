from __future__ import annotations

from datetime import datetime, timedelta

from chimera.cases import aggregate_identity_cases
from chimera.data_loader import AuthEvent
from chimera.scoring import AnomalyResult


def _event(offset_minutes: int, **kwargs) -> AuthEvent:
    return AuthEvent(
        timestamp=datetime(2026, 1, 1, 12, 0, 0) + timedelta(minutes=offset_minutes),
        user_id=kwargs.get("user_id", "alice"),
        event_type=kwargs.get("event_type", "login"),
        ip_address=kwargs.get("ip_address", "203.0.113.10"),
        asn=kwargs.get("asn", "AS64500"),
        country_code=kwargs.get("country_code", "US"),
        user_agent=kwargs.get("user_agent", "ua"),
        device_fingerprint=kwargs.get("device_fingerprint", "dev-a"),
        session_id=kwargs.get("session_id", "sess-a"),
        success=kwargs.get("success", True),
    )


def _result(index: int, event: AuthEvent, **signals) -> AnomalyResult:
    return AnomalyResult(
        event_index=index,
        user_id=event.user_id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        anomaly_score=-0.9,
        is_anomaly=True,
        confidence=0.95,
        research_signals=signals,
        research_reasons=[f"reason-{index}"],
        raw_event=event,
    )


def test_session_takeover_case_groups_shared_user_and_session():
    events = [
        _event(0, user_id="alice", session_id="sess-1", ip_address="198.51.100.10"),
        _event(5, user_id="alice", session_id="sess-1", ip_address="198.51.100.10", event_type="session_refresh"),
    ]
    results = [
        _result(0, events[0], identity_takeover_score=0.8, identity_takeover_sequence_score=0.5),
        _result(1, events[1], identity_takeover_score=0.82, identity_takeover_sequence_score=0.7),
    ]

    cases = aggregate_identity_cases(results)
    assert len(cases) == 1
    assert cases[0].case_type == "session_takeover_case"
    assert cases[0].involved_users == ["alice"]
    assert cases[0].representative_event_indices == [0, 1]


def test_password_spray_case_groups_shared_ip_across_users():
    events = [
        _event(0, user_id="alice", ip_address="198.51.100.50", session_id="sess-a", success=False, event_type="failed_login"),
        _event(1, user_id="bob", ip_address="198.51.100.50", session_id="sess-b", success=False, event_type="failed_login"),
    ]
    results = [
        _result(0, events[0], identity_password_spray_score=0.7),
        _result(1, events[1], identity_password_spray_score=0.72),
    ]

    cases = aggregate_identity_cases(results)
    assert len(cases) == 1
    assert cases[0].case_type == "password_spray_case"
    assert sorted(cases[0].involved_users) == ["alice", "bob"]


def test_low_and_slow_case_keeps_far_apart_events_in_same_case_window():
    events = [
        _event(0, user_id="alice", ip_address="203.0.113.77", success=False, event_type="failed_login"),
        _event(120, user_id="bob", ip_address="203.0.113.77", success=False, event_type="failed_login"),
    ]
    results = [
        _result(0, events[0], identity_low_and_slow_score=0.66),
        _result(1, events[1], identity_low_and_slow_score=0.69),
    ]

    cases = aggregate_identity_cases(results)
    assert len(cases) == 1
    assert cases[0].case_type == "low_and_slow_campaign_case"


def test_coordinated_case_requires_shared_evidence_across_multiple_users():
    events = [
        _event(0, user_id="alice", ip_address="192.0.2.1", device_fingerprint="shared-dev"),
        _event(2, user_id="bob", ip_address="192.0.2.1", device_fingerprint="shared-dev"),
    ]
    results = [
        _result(0, events[0], identity_campaign_score=0.7, identity_relationship_score=0.65),
        _result(1, events[1], identity_campaign_score=0.75, identity_relationship_score=0.67),
    ]

    cases = aggregate_identity_cases(results)
    assert any(case.case_type == "coordinated_identity_campaign_case" for case in cases)


def test_no_false_clustering_when_shared_evidence_absent():
    events = [
        _event(0, user_id="alice", ip_address="192.0.2.10", device_fingerprint="dev-a"),
        _event(1, user_id="bob", ip_address="192.0.2.11", device_fingerprint="dev-b"),
    ]
    results = [
        _result(0, events[0], identity_campaign_score=0.7, identity_relationship_score=0.2),
        _result(1, events[1], identity_campaign_score=0.7, identity_relationship_score=0.2),
    ]

    cases = aggregate_identity_cases(results)
    coordinated = [case for case in cases if case.case_type == "coordinated_identity_campaign_case"]
    assert coordinated == []

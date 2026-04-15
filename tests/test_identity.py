from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np

from chimera.config import ChimeraConfig
from chimera.data_loader import AuthEvent
from chimera.feature_engineering import FeatureEngineer
from chimera.identity import IdentityResearchAnalyzer


def _event(
    user_id: str,
    minute_offset: int,
    *,
    ip: str,
    device: str,
    country: str = "NG",
    asn: str = "64512",
    user_agent: str | None = None,
    session_id: str | None = None,
) -> AuthEvent:
    base = datetime(2026, 1, 1, 9, 0, 0)
    return AuthEvent(
        timestamp=base + timedelta(minutes=minute_offset),
        user_id=user_id,
        event_type="login",
        ip_address=ip,
        asn=asn,
        country_code=country,
        user_agent=user_agent,
        device_fingerprint=device,
        session_id=session_id,
        success=True,
    )


class TestIdentityResearchAnalyzer:
    def test_stable_session_boundaries(self):
        analyzer = IdentityResearchAnalyzer(session_gap_minutes=30)
        events = [
            _event("alice", 0, ip="10.0.0.1", device="dev-a"),
            _event("alice", 10, ip="10.0.0.1", device="dev-a"),
            _event("alice", 90, ip="10.0.0.2", device="dev-b"),
        ]
        signals = analyzer.fit_transform(events)
        assert signals[0].features["identity_session_size"] == 1.0
        assert signals[1].features["identity_session_size"] == 2.0
        assert signals[2].features["identity_session_size"] == 1.0

    def test_deterministic_ordering(self):
        analyzer = IdentityResearchAnalyzer()
        events = [
            _event("alice", 20, ip="10.0.0.2", device="dev-a"),
            _event("alice", 0, ip="10.0.0.1", device="dev-a"),
            _event("alice", 5, ip="10.0.0.1", device="dev-a"),
        ]
        analyzer.fit(events)
        signals = analyzer.transform(events)
        assert len(signals) == len(events)
        assert all(signal.event_index == idx for idx, signal in enumerate(signals))

    def test_shared_entity_and_sync_detection(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=20)
        events = [
            _event("alice", 0, ip="10.0.0.9", device="shared-device"),
            _event("bob", 5, ip="10.0.0.9", device="shared-device"),
            _event("carol", 40, ip="10.0.0.4", device="device-c"),
        ]
        signals = analyzer.fit_transform(events)
        assert signals[1].features["identity_shared_ip_users"] >= 1.0
        assert signals[1].features["identity_shared_device_users"] >= 1.0
        assert signals[1].features["identity_shared_infra_pair_users"] >= 1.0
        assert signals[1].features["identity_infra_burst_peer_count"] >= 1.0
        assert signals[1].features["identity_sync_peer_count"] >= 1.0
        assert signals[1].reasons

    def test_takeover_transition_and_privileged_follow_on(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=30)
        base = datetime(2026, 1, 1, 9, 0, 0)
        events = [
            AuthEvent(
                timestamp=base,
                user_id="alice",
                event_type="login",
                ip_address="10.0.0.1",
                asn="64512",
                country_code="NG",
                device_fingerprint="dev-a",
                session_id="sess-1",
                auth_method="password",
                mfa_used=True,
                success=True,
            ),
            AuthEvent(
                timestamp=base + timedelta(minutes=3),
                user_id="alice",
                event_type="session_refresh",
                ip_address="185.220.1.5",
                asn="64496",
                country_code="RU",
                device_fingerprint="dev-x",
                session_id="sess-1",
                auth_method="token_refresh",
                mfa_used=False,
                success=True,
            ),
            AuthEvent(
                timestamp=base + timedelta(minutes=6),
                user_id="alice",
                event_type="privileged_action",
                ip_address="185.220.1.5",
                asn="64496",
                country_code="RU",
                device_fingerprint="dev-x",
                session_id="sess-1",
                auth_method="api_key",
                mfa_used=False,
                success=True,
            ),
        ]
        signals = analyzer.fit_transform(events)

        assert signals[1].features["identity_takeover_transition"] >= 0.6
        assert signals[1].features["identity_session_context_shift"] >= 0.6
        assert signals[2].features["identity_privileged_escalation"] >= 1.0
        assert signals[2].features["identity_fusion_score"] >= signals[0].features["identity_fusion_score"]

    def test_mfa_bypass_suspicion_after_mfa_failures(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=30)
        base = datetime(2026, 1, 1, 9, 0, 0)
        events = [
            AuthEvent(
                timestamp=base,
                user_id="alice",
                event_type="mfa_failure",
                auth_method="mfa",
                mfa_used=True,
                success=False,
            ),
            AuthEvent(
                timestamp=base + timedelta(minutes=2),
                user_id="alice",
                event_type="mfa_failure",
                auth_method="mfa",
                mfa_used=True,
                success=False,
            ),
            AuthEvent(
                timestamp=base + timedelta(minutes=5),
                user_id="alice",
                event_type="login",
                auth_method="password",
                mfa_used=False,
                success=True,
            ),
        ]
        signals = analyzer.fit_transform(events)

        assert signals[2].features["identity_mfa_bypass_suspicion"] >= 1.0
        assert any("without MFA" in reason for reason in signals[2].reasons)


class TestFeatureEngineerIdentity:
    def test_identity_features_present_when_enabled(self):
        events = [
            _event("alice", 0, ip="10.0.0.1", device="shared-device"),
            _event("bob", 2, ip="10.0.0.1", device="shared-device"),
            _event("alice", 4, ip="10.0.0.2", device="dev-a", country="US"),
        ]
        engineer = FeatureEngineer(enable_identity_research=True)
        features_df = engineer.fit_transform(events)
        numeric = engineer.get_numeric_features(features_df)

        assert "identity_fusion_score" in features_df.columns
        assert "identity_takeover_score" in features_df.columns
        assert "identity_reasons" in features_df.columns
        assert "identity_sequence_score" in numeric.columns
        assert "identity_shared_infra_pair_users" in numeric.columns
        assert "identity_infra_burst_peer_count" in numeric.columns
        assert "identity_geo_velocity_score" in numeric.columns
        assert "identity_high_risk_country" in numeric.columns
        assert "identity_password_spray_score" in numeric.columns
        assert "identity_low_and_slow_score" in numeric.columns
        assert "identity_campaign_score" in numeric.columns
        assert "identity_takeover_sequence_score" in numeric.columns
        assert numeric["identity_relationship_score"].max() > 0.0

    def test_baseline_unchanged_when_disabled(self):
        events = [
            _event("alice", 0, ip="10.0.0.1", device="dev-a"),
            _event("alice", 5, ip="10.0.0.1", device="dev-a"),
        ]
        disabled = FeatureEngineer(enable_identity_research=False).fit_transform(events)
        enabled = FeatureEngineer(enable_identity_research=True).fit_transform(events)

        assert "identity_fusion_score" not in disabled.columns
        assert "identity_fusion_score" in enabled.columns

    def test_fit_transform_uses_only_prior_history(self):
        events = [
            _event("alice", 0, ip="10.0.0.1", device="dev-a"),
            _event("alice", 5, ip="10.0.0.2", device="dev-b"),
        ]
        features_df = FeatureEngineer(enable_identity_research=True).fit_transform(events)

        assert features_df.iloc[0]["events_last_hour"] == 0.0
        assert features_df.iloc[0]["unique_ips_24h"] == 1.0
        assert features_df.iloc[0]["unique_devices_24h"] == 1.0
        assert features_df.iloc[1]["is_known_ip"] == 0.0
        assert features_df.iloc[1]["events_last_hour"] == 1.0

    def test_identity_transform_is_causal_after_fit(self):
        train_events = [
            _event("alice", 0, ip="10.0.0.1", device="dev-a"),
        ]
        test_events = [
            _event("bob", 10, ip="10.0.0.9", device="shared-device"),
            _event("carol", 11, ip="10.0.0.9", device="shared-device"),
        ]
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=20)
        analyzer.fit(train_events)
        signals = analyzer.transform(test_events)

        assert signals[0].features["identity_shared_ip_users"] == 0.0
        assert signals[1].features["identity_shared_ip_users"] >= 1.0

    def test_infrastructure_pair_overlap_is_causal_and_distinct_user_based(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=20)
        events = [
            _event("alice", 0, ip="10.0.0.9", device="dev-a", asn="64512"),
            _event("alice", 2, ip="10.0.0.9", device="dev-a", asn="64512"),
            _event("bob", 4, ip="10.0.0.9", device="dev-b", asn="64512"),
        ]

        signals = analyzer.fit_transform(events)

        assert signals[0].features["identity_shared_infra_pair_users"] == 0.0
        assert signals[1].features["identity_shared_infra_pair_users"] == 0.0
        assert signals[2].features["identity_shared_infra_pair_users"] == 1.0
        assert any("infrastructure pair" in reason for reason in signals[2].reasons)

    def test_infrastructure_burst_peers_capture_recent_multi_user_convergence(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=10)
        events = [
            _event("alice", 0, ip="10.0.0.9", device="dev-a", asn="64512"),
            _event("bob", 1, ip="10.0.0.9", device="dev-b", asn="64512"),
            _event("carol", 2, ip="10.0.0.9", device="dev-c", asn="64512"),
            _event("dave", 20, ip="10.0.0.9", device="dev-d", asn="64512"),
        ]

        signals = analyzer.fit_transform(events)

        assert signals[0].features["identity_infra_burst_peer_count"] == 0.0
        assert signals[1].features["identity_infra_burst_peer_count"] >= 1.0
        assert signals[2].features["identity_infra_burst_peer_count"] >= 2.0
        assert signals[3].features["identity_infra_burst_peer_count"] == 0.0
        assert any(
            "converged on the same infrastructure pair" in reason
            for reason in signals[2].reasons
        )

    def test_session_concurrency_and_replay_signals(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=10)
        events = [
            _event(
                "alice",
                0,
                ip="10.0.0.1",
                device="dev-a",
                user_agent="Mozilla/5.0",
                session_id="sess-1",
            ),
            _event(
                "alice",
                1,
                ip="185.220.1.4",
                device="dev-x",
                user_agent="python-requests/2.31",
                country="RU",
                asn="64496",
                session_id="sess-1",
            ),
            AuthEvent(
                timestamp=datetime(2026, 1, 1, 9, 2, 0),
                user_id="alice",
                event_type="session_refresh",
                ip_address="185.220.1.4",
                asn="64496",
                country_code="RU",
                user_agent="python-requests/2.31",
                device_fingerprint="dev-x",
                session_id="sess-1",
                success=True,
            ),
            AuthEvent(
                timestamp=datetime(2026, 1, 1, 9, 2, 1),
                user_id="alice",
                event_type="session_refresh",
                ip_address="185.220.1.4",
                asn="64496",
                country_code="RU",
                user_agent="python-requests/2.31",
                device_fingerprint="dev-x",
                session_id="sess-1",
                success=True,
            ),
            AuthEvent(
                timestamp=datetime(2026, 1, 1, 9, 2, 2),
                user_id="alice",
                event_type="session_refresh",
                ip_address="185.220.1.4",
                asn="64496",
                country_code="RU",
                user_agent="python-requests/2.31",
                device_fingerprint="dev-x",
                session_id="sess-1",
                success=True,
            ),
            AuthEvent(
                timestamp=datetime(2026, 1, 1, 9, 2, 3),
                user_id="alice",
                event_type="session_refresh",
                ip_address="185.220.1.4",
                asn="64496",
                country_code="RU",
                user_agent="python-requests/2.31",
                device_fingerprint="dev-x",
                session_id="sess-1",
                success=True,
            ),
        ]

        signals = analyzer.fit_transform(events)

        assert signals[1].features["identity_session_concurrency"] >= 0.5
        assert signals[1].features["identity_session_fingerprint_drift"] >= 0.5
        assert signals[-1].features["identity_session_replay_burst"] >= 0.5

    def test_geo_velocity_score_flags_implausible_travel(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=90)
        events = [
            _event("alice", 0, ip="10.0.0.1", device="dev-a", country="US", asn="64512"),
            _event("alice", 30, ip="185.220.1.5", device="dev-b", country="RU", asn="64496"),
        ]

        signals = analyzer.fit_transform(events)

        assert signals[1].features["identity_geo_velocity_flag"] >= 1.0
        assert signals[1].features["identity_geo_velocity_score"] > 0.0
        assert signals[1].features["identity_high_risk_country"] >= 1.0

    def test_campaign_scores_capture_password_spray_and_low_and_slow_patterns(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=30)
        base = datetime(2026, 1, 1, 9, 0, 0)
        events = [
            AuthEvent(
                timestamp=base + timedelta(minutes=offset),
                user_id=user_id,
                event_type="failed_login",
                ip_address="203.0.113.10",
                asn="64512",
                country_code="NG",
                device_fingerprint=f"dev-{user_id}",
                success=False,
            )
            for offset, user_id in [
                (0, "alice"),
                (10, "bob"),
                (20, "carol"),
                (70, "dave"),
                (120, "erin"),
            ]
        ]

        signals = analyzer.fit_transform(events)

        assert signals[2].features["identity_password_spray_score"] > 0.0
        assert signals[-1].features["identity_low_and_slow_score"] > 0.0
        assert signals[-1].features["identity_campaign_score"] > 0.0

    def test_takeover_sequence_score_requires_ordered_progression(self):
        analyzer = IdentityResearchAnalyzer(relation_window_minutes=20)
        base = datetime(2026, 1, 1, 9, 0, 0)
        events = [
            AuthEvent(
                timestamp=base,
                user_id="alice",
                event_type="login",
                ip_address="10.0.0.1",
                asn="64512",
                country_code="NG",
                device_fingerprint="dev-a",
                session_id="sess-seq",
                auth_method="password",
                success=True,
            ),
            AuthEvent(
                timestamp=base + timedelta(minutes=2),
                user_id="alice",
                event_type="session_refresh",
                ip_address="185.220.1.4",
                asn="64496",
                country_code="RU",
                device_fingerprint="dev-x",
                session_id="sess-seq",
                auth_method="token_refresh",
                success=True,
            ),
            AuthEvent(
                timestamp=base + timedelta(minutes=4),
                user_id="alice",
                event_type="privileged_action",
                ip_address="185.220.1.4",
                asn="64496",
                country_code="RU",
                device_fingerprint="dev-x",
                session_id="sess-seq",
                auth_method="api_key",
                success=True,
            ),
        ]

        signals = analyzer.fit_transform(events)

        assert signals[0].features["identity_takeover_sequence_score"] == 0.0
        assert signals[1].features["identity_takeover_sequence_score"] >= 0.5
        assert signals[2].features["identity_takeover_sequence_score"] >= 1.0


class TestIdentityConfig:
    def test_identity_section_round_trip(self, tmp_path):
        cfg = ChimeraConfig()
        cfg.identity_research.enabled = True
        cfg.identity_research.relation_window_minutes = 20
        cfg.evaluation.attack_families = ["session_hijack", "coordinated_campaign"]

        path = tmp_path / "chimera_identity.json"
        cfg.save(path)
        loaded = ChimeraConfig.load(path)

        assert loaded.identity_research.enabled is True
        assert loaded.identity_research.relation_window_minutes == 20
        assert loaded.identity_research.scoring_hard_floor_enabled is True
        assert loaded.identity_research.takeover_hard_floor == 0.58
        assert loaded.evaluation.attack_families == [
            "session_hijack",
            "coordinated_campaign",
        ]

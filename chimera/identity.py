"""
chimera.identity - Structured identity-behavior reasoning primitives.

This module adds deterministic, offline-first research signals that model
authentication behavior as short sequences plus local relationship graphs.
The goal is not to replace the existing detectors, but to provide additive
signals that can be fused with them and inspected directly by researchers.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import asin, cos, radians, sin, sqrt
from statistics import median
from typing import Optional, Any

import numpy as np

from chimera._native.rust_graph import (
    ordered_takeover_sequence_progress,
    shared_pair_prior_counts,
    shared_pair_recent_peer_counts,
)
from chimera.data_loader import AuthEvent


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _safe_median(values: list[float], default: float) -> float:
    if not values:
        return default
    return float(median(values))


def _median_abs_deviation(values: list[float], center: float) -> float:
    if not values:
        return 1.0
    deviations = [abs(v - center) for v in values]
    mad = _safe_median(deviations, 1.0)
    return max(mad, 1.0)


_COUNTRY_COORDINATES = {
    "NG": (9.0820, 8.6753),
    "US": (39.8283, -98.5795),
    "RU": (61.5240, 105.3188),
    "NL": (52.1326, 5.2913),
    "SG": (1.3521, 103.8198),
    "DE": (51.1657, 10.4515),
    "GB": (55.3781, -3.4360),
    "BR": (-14.2350, -51.9253),
    "ZA": (-30.5595, 22.9375),
    "JP": (36.2048, 138.2529),
}

_HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "SY"}


def _country_distance_km(country_a: str, country_b: str) -> float:
    coords_a = _COUNTRY_COORDINATES.get(country_a)
    coords_b = _COUNTRY_COORDINATES.get(country_b)
    if coords_a is None or coords_b is None:
        return 0.0
    lat1, lon1 = coords_a
    lat2, lon2 = coords_b
    radius_km = 6371.0
    d_lat = radians(lat2 - lat1)
    d_lon = radians(lon2 - lon1)
    a = (
        sin(d_lat / 2) ** 2
        + cos(radians(lat1)) * cos(radians(lat2)) * sin(d_lon / 2) ** 2
    )
    return radius_km * 2 * asin(sqrt(a))


@dataclass
class IdentitySignal:
    """Per-event research signals and explanations."""

    event_index: int
    user_id: str
    sequence_score: float
    relationship_score: float
    fusion_score: float
    features: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


class IdentityResearchAnalyzer:
    """Deterministic identity sequence and relationship analyzer."""

    FEATURE_COLUMNS = [
        "identity_sequence_score",
        "identity_relationship_score",
        "identity_fusion_score",
        "identity_session_position",
        "identity_session_size",
        "identity_burst_score",
        "identity_interval_deviation",
        "identity_geo_velocity_flag",
        "identity_shared_ip_users",
        "identity_shared_device_users",
        "identity_shared_asn_users",
        "identity_shared_infra_pair_users",
        "identity_infra_burst_peer_count",
        "identity_session_concurrency",
        "identity_session_replay_burst",
        "identity_session_fingerprint_drift",
        "identity_geo_velocity_score",
        "identity_high_risk_country",
        "identity_sync_peer_count",
        "identity_fanout_score",
        "identity_password_spray_score",
        "identity_low_and_slow_score",
        "identity_campaign_score",
        "identity_takeover_sequence_score",
        "identity_takeover_score",
        "identity_takeover_support",
        "identity_mfa_bypass_suspicion",
        "identity_session_novelty",
        "identity_session_context_shift",
        "identity_takeover_transition",
        "identity_privileged_escalation",
    ]

    def __init__(
        self,
        session_gap_minutes: int = 45,
        burst_window_minutes: int = 5,
        relation_window_minutes: int = 15,
        max_shared_entity_users: int = 10,
    ) -> None:
        self.session_gap = timedelta(minutes=session_gap_minutes)
        self.burst_window = timedelta(minutes=burst_window_minutes)
        self.relation_window = timedelta(minutes=relation_window_minutes)
        self.max_shared_entity_users = max(2, max_shared_entity_users)

        self._ip_users: dict[str, set[str]] = {}
        self._device_users: dict[str, set[str]] = {}
        self._asn_users: dict[str, set[str]] = {}
        self._ip_timeline: dict[str, tuple[list[datetime], list[str]]] = {}
        self._device_timeline: dict[str, tuple[list[datetime], list[str]]] = {}
        self._user_interval_median: dict[str, float] = {}
        self._user_interval_mad: dict[str, float] = {}
        self._user_session_size_median: dict[str, float] = {}
        self._user_ips: dict[str, set[str]] = {}
        self._user_devices: dict[str, set[str]] = {}
        self._user_countries: dict[str, set[str]] = {}
        self._user_asns: dict[str, set[str]] = {}
        self._user_session_ids: dict[str, set[str]] = {}
        self._session_contexts: dict[tuple[str, str], dict[str, Any]] = {}
        self._session_recent_events: dict[str, list[dict[str, Any]]] = {}
        self._ip_failure_events: dict[str, list[dict[str, Any]]] = {}
        self._recent_mfa_failures: dict[str, list[datetime]] = {}
        self._fitted = False

    def fit(self, events: list[AuthEvent]) -> "IdentityResearchAnalyzer":
        """Fit identity state from historical events."""
        _, final_state = self._run(events, initial_state=None, emit_signals=False)
        self._apply_state(final_state)
        self._fitted = True
        return self

    def fit_transform(self, events: list[AuthEvent]) -> list[IdentitySignal]:
        """Emit causal signals while fitting state from the same stream."""
        signals, final_state = self._run(events, initial_state=None, emit_signals=True)
        self._apply_state(final_state)
        self._fitted = True
        return signals

    def transform(self, events: list[AuthEvent]) -> list[IdentitySignal]:
        """Generate per-event signals aligned to the input event order."""
        if not self._fitted:
            raise RuntimeError("Call fit() before transform().")
        signals, _ = self._run(events, initial_state=self._snapshot_state(), emit_signals=True)
        return signals

    def _snapshot_state(self) -> dict[str, Any]:
        return {
            "ip_users": defaultdict(
                set, {key: set(values) for key, values in self._ip_users.items()}
            ),
            "device_users": defaultdict(
                set, {key: set(values) for key, values in self._device_users.items()}
            ),
            "asn_users": defaultdict(
                set, {key: set(values) for key, values in self._asn_users.items()}
            ),
            "ip_timeline": defaultdict(
                lambda: ([], []),
                {
                    key: (list(times), list(users))
                    for key, (times, users) in self._ip_timeline.items()
                },
            ),
            "device_timeline": defaultdict(
                lambda: ([], []),
                {
                    key: (list(times), list(users))
                    for key, (times, users) in self._device_timeline.items()
                },
            ),
            "interval_history": defaultdict(
                list,
                {
                    user_id: [center, self._user_interval_mad.get(user_id, 1.0)]
                    for user_id, center in self._user_interval_median.items()
                },
            ),
            "session_history": defaultdict(
                list,
                {
                    user_id: [median_value]
                    for user_id, median_value in self._user_session_size_median.items()
                },
            ),
            "user_ips": defaultdict(
                set, {user_id: set(values) for user_id, values in self._user_ips.items()}
            ),
            "user_devices": defaultdict(
                set,
                {user_id: set(values) for user_id, values in self._user_devices.items()},
            ),
            "user_countries": defaultdict(
                set,
                {user_id: set(values) for user_id, values in self._user_countries.items()},
            ),
            "user_asns": defaultdict(
                set, {user_id: set(values) for user_id, values in self._user_asns.items()}
            ),
            "user_session_ids": defaultdict(
                set,
                {
                    user_id: set(values)
                    for user_id, values in self._user_session_ids.items()
                },
            ),
            "session_contexts": {
                key: dict(value) for key, value in self._session_contexts.items()
            },
            "session_recent_events": defaultdict(
                list,
                {
                    session_id: [dict(value) for value in values]
                    for session_id, values in self._session_recent_events.items()
                },
            ),
            "ip_failure_events": defaultdict(
                list,
                {
                    ip_address: [dict(value) for value in values]
                    for ip_address, values in self._ip_failure_events.items()
                },
            ),
            "recent_mfa_failures": defaultdict(
                list,
                {
                    user_id: list(values)
                    for user_id, values in self._recent_mfa_failures.items()
                },
            ),
            "last_event": {},
            "active_session_size": defaultdict(int),
            "active_session_last_ts": {},
        }

    def _apply_state(self, state: dict[str, Any]) -> None:
        self._ip_users = dict(state["ip_users"])
        self._device_users = dict(state["device_users"])
        self._asn_users = dict(state["asn_users"])
        self._ip_timeline = dict(state["ip_timeline"])
        self._device_timeline = dict(state["device_timeline"])
        self._user_interval_median = {
            user_id: _safe_median(values, 3600.0)
            for user_id, values in state["interval_history"].items()
        }
        self._user_interval_mad = {
            user_id: _median_abs_deviation(values, self._user_interval_median[user_id])
            for user_id, values in state["interval_history"].items()
        }
        self._user_session_size_median = {
            user_id: _safe_median(values, 1.0)
            for user_id, values in state["session_history"].items()
        }
        self._user_ips = {
            user_id: set(values) for user_id, values in state["user_ips"].items()
        }
        self._user_devices = {
            user_id: set(values) for user_id, values in state["user_devices"].items()
        }
        self._user_countries = {
            user_id: set(values) for user_id, values in state["user_countries"].items()
        }
        self._user_asns = {
            user_id: set(values) for user_id, values in state["user_asns"].items()
        }
        self._user_session_ids = {
            user_id: set(values) for user_id, values in state["user_session_ids"].items()
        }
        self._session_contexts = {
            key: dict(value) for key, value in state["session_contexts"].items()
        }
        self._session_recent_events = {
            session_id: [dict(value) for value in values]
            for session_id, values in state["session_recent_events"].items()
        }
        self._ip_failure_events = {
            ip_address: [dict(value) for value in values]
            for ip_address, values in state["ip_failure_events"].items()
        }
        self._recent_mfa_failures = {
            user_id: list(values)
            for user_id, values in state["recent_mfa_failures"].items()
        }

    def _run(
        self,
        events: list[AuthEvent],
        *,
        initial_state: Optional[dict[str, Any]],
        emit_signals: bool,
    ) -> tuple[list[IdentitySignal], dict[str, Any]]:
        state = initial_state or {
            "ip_users": defaultdict(set),
            "device_users": defaultdict(set),
            "asn_users": defaultdict(set),
            "ip_timeline": defaultdict(lambda: ([], [])),
            "device_timeline": defaultdict(lambda: ([], [])),
            "interval_history": defaultdict(list),
            "session_history": defaultdict(list),
            "user_ips": defaultdict(set),
            "user_devices": defaultdict(set),
            "user_countries": defaultdict(set),
            "user_asns": defaultdict(set),
            "user_session_ids": defaultdict(set),
            "session_contexts": {},
            "session_recent_events": defaultdict(list),
            "ip_failure_events": defaultdict(list),
            "recent_mfa_failures": defaultdict(list),
            "last_event": {},
            "active_session_size": defaultdict(int),
            "active_session_last_ts": {},
        }
        signals: list[Optional[IdentitySignal]] = [None] * len(events)
        indexed_events = sorted(enumerate(events), key=lambda item: (item[1].timestamp, item[0]))
        prior_infra_pair_users = self._compute_prior_infra_pair_users(indexed_events)
        infra_burst_peer_counts = self._compute_recent_infra_burst_peers(indexed_events)
        takeover_sequence_progress = self._compute_takeover_sequence_progress(indexed_events)

        for sorted_index, (original_index, event) in enumerate(indexed_events):
            previous_event = state["last_event"].get(event.user_id)
            session_position, session_size_so_far = self._session_state_for_event(
                state,
                event,
            )
            if emit_signals:
                signals[original_index] = self._signal_for_event(
                    original_index=original_index,
                    event=event,
                    previous_event=previous_event,
                    session_position=session_position,
                    session_size=session_size_so_far,
                    ip_users=state["ip_users"],
                    device_users=state["device_users"],
                    asn_users=state["asn_users"],
                    ip_timeline=state["ip_timeline"],
                    device_timeline=state["device_timeline"],
                    interval_history=state["interval_history"],
                    session_history=state["session_history"],
                    user_ips=state["user_ips"],
                    user_devices=state["user_devices"],
                    user_countries=state["user_countries"],
                    user_asns=state["user_asns"],
                    user_session_ids=state["user_session_ids"],
                    session_contexts=state["session_contexts"],
                    session_recent_events=state["session_recent_events"],
                    ip_failure_events=state["ip_failure_events"],
                    recent_mfa_failures=state["recent_mfa_failures"],
                    shared_infra_pair_users=float(prior_infra_pair_users[sorted_index]),
                    infra_burst_peer_count=float(infra_burst_peer_counts[sorted_index]),
                    takeover_sequence_score=float(takeover_sequence_progress[sorted_index]),
                )
            self._update_state(state, event, previous_event)

        return [signal for signal in signals if signal is not None], state

    def _session_state_for_event(
        self,
        state: dict[str, Any],
        event: AuthEvent,
    ) -> tuple[int, int]:
        user_id = event.user_id
        last_session_ts = state["active_session_last_ts"].get(user_id)
        current_size = int(state["active_session_size"].get(user_id, 0))
        if last_session_ts is None or event.timestamp - last_session_ts > self.session_gap:
            current_size = 0
        return current_size, current_size + 1

    def _update_state(
        self,
        state: dict[str, Any],
        event: AuthEvent,
        previous_event: Optional[AuthEvent],
    ) -> None:
        user_id = event.user_id
        last_session_ts = state["active_session_last_ts"].get(user_id)
        current_size = int(state["active_session_size"].get(user_id, 0))
        if last_session_ts is None or event.timestamp - last_session_ts > self.session_gap:
            if current_size > 0:
                state["session_history"][user_id].append(float(current_size))
            current_size = 0
        current_size += 1
        state["active_session_size"][user_id] = current_size
        state["active_session_last_ts"][user_id] = event.timestamp

        if previous_event is not None:
            gap_seconds = max((event.timestamp - previous_event.timestamp).total_seconds(), 0.0)
            state["interval_history"][user_id].append(float(gap_seconds))

        state["last_event"][user_id] = event

        if event.ip_address:
            state["user_ips"][user_id].add(event.ip_address)
            state["ip_users"][event.ip_address].add(user_id)
            times, users = state["ip_timeline"][event.ip_address]
            times.append(event.timestamp)
            users.append(user_id)
        if event.device_fingerprint:
            state["user_devices"][user_id].add(event.device_fingerprint)
            state["device_users"][event.device_fingerprint].add(user_id)
            times, users = state["device_timeline"][event.device_fingerprint]
            times.append(event.timestamp)
            users.append(user_id)
        if event.asn:
            state["user_asns"][user_id].add(event.asn)
            state["asn_users"][event.asn].add(user_id)
        if event.country_code:
            state["user_countries"][user_id].add(event.country_code)
        mfa_window = max(self.relation_window, timedelta(minutes=30))
        recent_failures = [
            ts
            for ts in state["recent_mfa_failures"][user_id]
            if event.timestamp - ts <= mfa_window
        ]
        if event.is_failure and event.mfa_used:
            recent_failures.append(event.timestamp)
        state["recent_mfa_failures"][user_id] = recent_failures
        if event.session_id:
            state["user_session_ids"][user_id].add(event.session_id)
            session_key = (user_id, event.session_id)
            session_context = state["session_contexts"].get(session_key)
            if session_context is None:
                state["session_contexts"][session_key] = {
                    "ip_address": event.ip_address,
                    "device_fingerprint": event.device_fingerprint,
                    "country_code": event.country_code,
                    "asn": event.asn,
                    "user_agent": event.user_agent,
                    "auth_method": event.auth_method,
                    "mfa_used": event.mfa_used,
                    "event_count": 1,
                }
            else:
                session_context["event_count"] = int(session_context.get("event_count", 0)) + 1
            recent_events = [
                item
                for item in state["session_recent_events"][event.session_id]
                if event.timestamp - item["timestamp"] <= self.relation_window
            ]
            recent_events.append(
                {
                    "timestamp": event.timestamp,
                    "user_id": event.user_id,
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "device_fingerprint": event.device_fingerprint,
                }
            )
            state["session_recent_events"][event.session_id] = recent_events

        if event.ip_address and event.is_failure:
            recent_failures = [
                item
                for item in state["ip_failure_events"][event.ip_address]
                if event.timestamp - item["timestamp"] <= self.relation_window * 8
            ]
            recent_failures.append(
                {
                    "timestamp": event.timestamp,
                    "user_id": event.user_id,
                }
            )
            state["ip_failure_events"][event.ip_address] = recent_failures

    def _signal_for_event(
        self,
        original_index: int,
        event: AuthEvent,
        previous_event: Optional[AuthEvent],
        session_position: int,
        session_size: int,
        ip_users: dict[str, set[str]],
        device_users: dict[str, set[str]],
        asn_users: dict[str, set[str]],
        ip_timeline: dict[str, tuple[list[datetime], list[str]]],
        device_timeline: dict[str, tuple[list[datetime], list[str]]],
        interval_history: dict[str, list[float]],
        session_history: dict[str, list[float]],
        user_ips: dict[str, set[str]],
        user_devices: dict[str, set[str]],
        user_countries: dict[str, set[str]],
        user_asns: dict[str, set[str]],
        user_session_ids: dict[str, set[str]],
        session_contexts: dict[tuple[str, str], dict[str, Any]],
        session_recent_events: dict[str, list[dict[str, Any]]],
        ip_failure_events: dict[str, list[dict[str, Any]]],
        recent_mfa_failures: dict[str, list[datetime]],
        shared_infra_pair_users: float,
        infra_burst_peer_count: float,
        takeover_sequence_score: float,
    ) -> IdentitySignal:
        reasons: list[str] = []

        shared_ip_users = float(len(ip_users.get(event.ip_address or "", set())))
        shared_device_users = float(
            len(device_users.get(event.device_fingerprint or "", set()))
        )
        shared_asn_users = float(len(asn_users.get(event.asn or "", set())))

        sync_peers = float(
            max(
                self._window_peer_count(
                    ip_timeline.get(event.ip_address or ""),
                    event.timestamp,
                    event.user_id,
                ),
                self._window_peer_count(
                    device_timeline.get(event.device_fingerprint or ""),
                    event.timestamp,
                    event.user_id,
                ),
                int(infra_burst_peer_count),
            )
        )

        fanout_score = _clamp01(
            max(
                shared_ip_users,
                shared_device_users,
                shared_asn_users,
                shared_infra_pair_users,
                infra_burst_peer_count,
            )
            / float(self.max_shared_entity_users)
        )

        interval_deviation = 0.0
        burst_score = 0.0
        geo_velocity_flag = 0.0
        geo_velocity_score = 0.0
        high_risk_country = 1.0 if (event.country_code or "") in _HIGH_RISK_COUNTRIES else 0.0
        ip_novelty = 0.0
        device_novelty = 0.0
        country_novelty = 0.0
        asn_novelty = 0.0
        session_novelty = 0.0
        session_context_shift = 0.0
        session_concurrency = 0.0
        session_replay_burst = 0.0
        session_fingerprint_drift = 0.0
        password_spray_score = 0.0
        low_and_slow_score = 0.0
        campaign_score = 0.0
        takeover_transition = 0.0
        privileged_escalation = 0.0
        mfa_bypass_suspicion = 0.0

        if event.ip_address and event.ip_address not in user_ips.get(event.user_id, set()):
            ip_novelty = 1.0
        if (
            event.device_fingerprint
            and event.device_fingerprint not in user_devices.get(event.user_id, set())
        ):
            device_novelty = 1.0
        if (
            event.country_code
            and event.country_code not in user_countries.get(event.user_id, set())
        ):
            country_novelty = 1.0
        if event.asn and event.asn not in user_asns.get(event.user_id, set()):
            asn_novelty = 1.0
        if event.session_id and event.session_id not in user_session_ids.get(event.user_id, set()):
            if event.event_type in {"session_refresh", "privileged_action"}:
                session_novelty = 1.0
        if event.success and event.mfa_used is False:
            prior_mfa_failures = len(recent_mfa_failures.get(event.user_id, []))
            if prior_mfa_failures >= 2:
                mfa_bypass_suspicion = 1.0

        session_context = None
        if event.session_id:
            session_context = session_contexts.get((event.user_id, event.session_id))
        if session_context is not None:
            context_deltas = sum(
                1
                for field_name in ("ip_address", "device_fingerprint", "country_code", "asn")
                if session_context.get(field_name) and getattr(event, field_name) and session_context.get(field_name) != getattr(event, field_name)
            )
            if context_deltas >= 2:
                session_context_shift = _clamp01(context_deltas / 3.0)
            if (
                event.user_agent
                and session_context.get("user_agent")
                and event.user_agent != session_context.get("user_agent")
            ):
                session_fingerprint_drift = max(session_fingerprint_drift, 0.5)
            if (
                event.event_type == "privileged_action"
                and context_deltas >= 1
            ):
                privileged_escalation = 1.0

        if event.session_id:
            recent_session_events = session_recent_events.get(event.session_id, [])
            concurrent_peers = [
                item
                for item in recent_session_events
                if item["user_id"] == event.user_id
                and (
                    (event.ip_address and item.get("ip_address") and item["ip_address"] != event.ip_address)
                    or (
                        event.user_agent
                        and item.get("user_agent")
                        and item["user_agent"] != event.user_agent
                    )
                )
            ]
            if concurrent_peers:
                session_concurrency = _clamp01(len(concurrent_peers) / 2.0)
                session_fingerprint_drift = max(session_fingerprint_drift, 1.0)

            if len(recent_session_events) >= 3:
                five_second_peers = [
                    item
                    for item in recent_session_events
                    if abs((event.timestamp - item["timestamp"]).total_seconds()) <= 5
                ]
                if len(five_second_peers) >= 3:
                    session_replay_burst = _clamp01(len(five_second_peers) / 6.0)

        if event.ip_address and event.is_failure:
            ip_failure_history = ip_failure_events.get(event.ip_address, [])
            local_failures = [
                item
                for item in ip_failure_history
                if event.timestamp - item["timestamp"] <= self.relation_window * 2
            ]
            slow_failures = [
                item
                for item in ip_failure_history
                if event.timestamp - item["timestamp"] <= self.relation_window * 8
            ]
            local_users = {
                item["user_id"] for item in local_failures if item["user_id"] != event.user_id
            }
            slow_users = {
                item["user_id"] for item in slow_failures if item["user_id"] != event.user_id
            }
            local_user_counts: dict[str, int] = defaultdict(int)
            for item in local_failures:
                local_user_counts[item["user_id"]] += 1
            local_unique_users = len(local_users)
            if local_unique_users >= 2:
                max_attempts_per_user = max(local_user_counts.values(), default=1)
                password_spray_score = _clamp01(
                    local_unique_users / 4.0
                    + max(0.0, (len(local_failures) - 2.0) / 8.0)
                    + max(0.0, (2.0 - max_attempts_per_user) / 4.0)
                )
            if len(slow_failures) >= 3 and len(slow_users) >= 2:
                oldest_ts = min(item["timestamp"] for item in slow_failures)
                span_seconds = max((event.timestamp - oldest_ts).total_seconds(), 0.0)
                short_burst_count = sum(
                    1
                    for item in slow_failures
                    if event.timestamp - item["timestamp"] <= self.burst_window
                )
                low_and_slow_score = _clamp01(
                    len(slow_users) / 4.0
                    + min(span_seconds / max(self.relation_window.total_seconds() * 4.0, 1.0), 1.0)
                    + max(0.0, (3.0 - short_burst_count) / 4.0)
                )

        if previous_event is not None:
            gap_seconds = max(
                (event.timestamp - previous_event.timestamp).total_seconds(),
                0.0,
            )
            user_intervals = interval_history.get(event.user_id, [])
            user_center = _safe_median(user_intervals, 3600.0)
            user_mad = _median_abs_deviation(user_intervals, user_center)
            interval_deviation = min(abs(gap_seconds - user_center) / user_mad, 10.0)
            burst_score = _clamp01(
                max(
                    0.0,
                    1.0 - (gap_seconds / max(self.burst_window.total_seconds(), 1.0)),
                )
            )

            if (
                previous_event.country_code
                and event.country_code
                and previous_event.country_code != event.country_code
                and gap_seconds < self.relation_window.total_seconds()
            ):
                geo_velocity_flag = 1.0
                distance_km = _country_distance_km(
                    previous_event.country_code,
                    event.country_code,
                )
                hours_between = max(gap_seconds / 3600.0, 0.01)
                implied_speed = distance_km / hours_between if distance_km > 0 else 0.0
                if implied_speed > 900.0 and distance_km > 500.0:
                    geo_velocity_score = _clamp01(implied_speed / 1800.0)
                elif distance_km > 0:
                    geo_velocity_score = _clamp01(distance_km / 12000.0)

            context_shift_count = sum(
                1
                for previous_value, current_value in (
                    (previous_event.ip_address, event.ip_address),
                    (previous_event.device_fingerprint, event.device_fingerprint),
                    (previous_event.country_code, event.country_code),
                    (previous_event.asn, event.asn),
                )
                if previous_value and current_value and previous_value != current_value
            )
            if (
                gap_seconds < self.relation_window.total_seconds()
                and context_shift_count >= 2
                and event.event_type in {"login", "session_refresh", "privileged_action"}
            ):
                takeover_transition = _clamp01(context_shift_count / 3.0)
                session_fingerprint_drift = max(
                    session_fingerprint_drift,
                    _clamp01(context_shift_count / 3.0),
                )
            if (
                event.event_type == "privileged_action"
                and context_shift_count >= 2
                and gap_seconds < self.relation_window.total_seconds()
            ):
                privileged_escalation = max(privileged_escalation, 1.0)

        session_position_norm = _clamp01(
            session_position / max(float(session_size - 1), 1.0)
        )
        session_size_baseline = _safe_median(session_history.get(event.user_id, []), 1.0)
        session_size_norm = _clamp01(
            session_size / max(session_size_baseline, 1.0)
        )

        sequence_score = _clamp01(
            (
                burst_score * 0.20
                + _clamp01(interval_deviation / 6.0) * 0.20
                + geo_velocity_flag * 0.15
                + geo_velocity_score * 0.20
                + _clamp01(max(session_size_norm - 1.0, 0.0)) * 0.05
                + max(ip_novelty, country_novelty, asn_novelty) * 0.10
                + device_novelty * 0.10
                + session_novelty * 0.10
                + session_context_shift * 0.15
                + session_concurrency * 0.20
                + session_replay_burst * 0.10
                + takeover_transition * 0.20
                + privileged_escalation * 0.15
                + takeover_sequence_score * 0.20
            )
        )
        relationship_score = _clamp01(
            (
                _clamp01((shared_ip_users - 1.0) / self.max_shared_entity_users) * 0.25
                + _clamp01((shared_device_users - 1.0) / self.max_shared_entity_users) * 0.25
                + _clamp01((shared_asn_users - 1.0) / self.max_shared_entity_users) * 0.10
                + _clamp01((shared_infra_pair_users - 1.0) / self.max_shared_entity_users) * 0.15
                + _clamp01(sync_peers / self.max_shared_entity_users) * 0.12
                + _clamp01(infra_burst_peer_count / self.max_shared_entity_users) * 0.08
                + fanout_score * 0.10
                + password_spray_score * 0.12
                + low_and_slow_score * 0.10
            )
        )
        campaign_score = _clamp01(
            password_spray_score * 0.45
            + low_and_slow_score * 0.35
            + _clamp01(sync_peers / self.max_shared_entity_users) * 0.10
            + fanout_score * 0.10
        )
        takeover_support = max(
            session_context_shift,
            session_concurrency,
            session_replay_burst,
            session_fingerprint_drift,
            takeover_sequence_score,
            takeover_transition,
            privileged_escalation,
        )
        takeover_score = _clamp01(
            (
                takeover_sequence_score * 0.30
                + takeover_transition * 0.35
                + session_context_shift * 0.25
                + session_concurrency * 0.25
                + session_replay_burst * 0.15
                + session_fingerprint_drift * 0.15
                + geo_velocity_score * 0.15
                + high_risk_country * 0.10
                + privileged_escalation * 0.20
                + mfa_bypass_suspicion * 0.20
                + campaign_score * 0.10
                + session_novelty * 0.10
                + max(ip_novelty, device_novelty, country_novelty, asn_novelty) * 0.10
            )
        )
        fusion_score = _clamp01((sequence_score + relationship_score) / 2.0)

        if burst_score >= 0.7:
            reasons.append(
                f"Rapid sequence cadence for {event.user_id} within the burst window."
            )
        if interval_deviation >= 3.0:
            reasons.append(
                f"Inter-event timing deviates sharply from {event.user_id}'s baseline rhythm."
            )
        if geo_velocity_flag:
            reasons.append(
                "Country transition occurred inside the suspicious relation window."
            )
        if geo_velocity_score >= 0.5:
            reasons.append(
                "The implied travel speed between session locations is operationally implausible."
            )
        if high_risk_country:
            reasons.append(
                "The session touched a country that is elevated in the local risk model."
            )
        if ip_novelty or country_novelty or asn_novelty:
            reasons.append(
                f"Network identity shifted outside {event.user_id}'s prior baseline."
            )
        if device_novelty:
            reasons.append(
                f"Device fingerprint is new for {event.user_id}."
            )
        if session_novelty:
            reasons.append(
                "Session activity appeared before this session identifier was historically established."
            )
        if session_context_shift >= 0.6:
            reasons.append(
                "An existing session shifted across multiple identity-context dimensions."
            )
        if session_concurrency >= 0.5:
            reasons.append(
                "The same session was active under divergent network or browser context."
            )
        if session_replay_burst >= 0.5:
            reasons.append(
                "The session generated a replay-like burst of requests in a very short window."
            )
        if session_fingerprint_drift >= 0.5:
            reasons.append(
                "Session fingerprint drift suggests token reuse under a changed client context."
            )
        if takeover_transition >= 0.6:
            reasons.append(
                "Rapid transition suggests a session continuation under a different identity context."
            )
        if privileged_escalation:
            reasons.append(
                "Privileged activity followed the suspicious session transition."
            )
        if takeover_sequence_score >= 0.5:
            reasons.append(
                "Observed an ordered takeover sequence from session establishment to follow-on privileged activity."
            )
        if mfa_bypass_suspicion:
            reasons.append(
                "Successful access without MFA followed repeated MFA-protected failures."
            )
        if password_spray_score >= 0.5:
            reasons.append(
                "Failure pattern resembles password spraying across multiple peer identities from one source."
            )
        if low_and_slow_score >= 0.5:
            reasons.append(
                "Distributed failures accumulated slowly enough to evade simple burst windows."
            )
        if campaign_score >= 0.5:
            reasons.append(
                "Local relationship evidence suggests a coordinated identity-abuse campaign."
            )
        if shared_ip_users > 2:
            reasons.append(
                f"IP address is shared across {int(shared_ip_users)} users."
            )
        if shared_device_users > 1:
            reasons.append(
                f"Device fingerprint is reused across {int(shared_device_users)} users."
            )
        if shared_infra_pair_users >= 1:
            reasons.append(
                "The same infrastructure pair has already appeared under another identity."
            )
        if infra_burst_peer_count >= 1:
            reasons.append(
                "Multiple peer identities recently converged on the same infrastructure pair."
            )
        if sync_peers > 0:
            reasons.append(
                f"Observed {int(sync_peers)} synchronized peer identities in the same local window."
            )

        features = {
            "identity_sequence_score": round(sequence_score, 6),
            "identity_relationship_score": round(relationship_score, 6),
            "identity_fusion_score": round(fusion_score, 6),
            "identity_session_position": round(session_position_norm, 6),
            "identity_session_size": float(session_size),
            "identity_burst_score": round(burst_score, 6),
            "identity_interval_deviation": round(interval_deviation, 6),
            "identity_geo_velocity_flag": round(geo_velocity_flag, 6),
            "identity_geo_velocity_score": round(geo_velocity_score, 6),
            "identity_high_risk_country": round(high_risk_country, 6),
            "identity_shared_ip_users": shared_ip_users,
            "identity_shared_device_users": shared_device_users,
            "identity_shared_asn_users": shared_asn_users,
            "identity_shared_infra_pair_users": shared_infra_pair_users,
            "identity_infra_burst_peer_count": infra_burst_peer_count,
            "identity_session_concurrency": round(session_concurrency, 6),
            "identity_session_replay_burst": round(session_replay_burst, 6),
            "identity_session_fingerprint_drift": round(session_fingerprint_drift, 6),
            "identity_sync_peer_count": sync_peers,
            "identity_fanout_score": round(fanout_score, 6),
            "identity_password_spray_score": round(password_spray_score, 6),
            "identity_low_and_slow_score": round(low_and_slow_score, 6),
            "identity_campaign_score": round(campaign_score, 6),
            "identity_takeover_sequence_score": round(takeover_sequence_score, 6),
            "identity_takeover_score": round(takeover_score, 6),
            "identity_takeover_support": round(takeover_support, 6),
            "identity_mfa_bypass_suspicion": round(mfa_bypass_suspicion, 6),
            "identity_session_novelty": round(session_novelty, 6),
            "identity_session_context_shift": round(session_context_shift, 6),
            "identity_takeover_transition": round(takeover_transition, 6),
            "identity_privileged_escalation": round(privileged_escalation, 6),
        }

        return IdentitySignal(
            event_index=original_index,
            user_id=event.user_id,
            sequence_score=sequence_score,
            relationship_score=relationship_score,
            fusion_score=fusion_score,
            features=features,
            reasons=reasons,
        )

    def _window_peer_count(
        self,
        timeline: Optional[tuple[list[datetime], list[str]]],
        ts: datetime,
        current_user: str,
    ) -> int:
        if timeline is None:
            return 0
        times, users = timeline
        lower = ts - self.relation_window
        upper = ts + self.relation_window
        left = bisect_left(times, lower)
        right = bisect_right(times, upper)
        peers = {
            users[i]
            for i in range(left, right)
            if users[i] != current_user
        }
        return len(peers)

    def _compute_prior_infra_pair_users(
        self,
        indexed_events: list[tuple[int, AuthEvent]],
    ) -> np.ndarray:
        pair_codes: list[int] = []
        user_codes: list[int] = []
        seen_pair_by_user: dict[str, set[str]] = defaultdict(set)
        self_history_flags: list[int] = []
        pair_encoder: dict[str, int] = {}
        user_encoder: dict[str, int] = {}
        next_pair_code = 1
        next_user_code = 1

        for _, event in indexed_events:
            pair_key = self._infrastructure_pair_key(event)
            self_history_flags.append(1 if pair_key in seen_pair_by_user[event.user_id] else 0)
            seen_pair_by_user[event.user_id].add(pair_key)
            if pair_key not in pair_encoder:
                pair_encoder[pair_key] = next_pair_code
                next_pair_code += 1
            if event.user_id not in user_encoder:
                user_encoder[event.user_id] = next_user_code
                next_user_code += 1
            pair_codes.append(pair_encoder[pair_key])
            user_codes.append(user_encoder[event.user_id])

        prior_counts = shared_pair_prior_counts(
            np.asarray(pair_codes, dtype=np.int64),
            np.asarray(user_codes, dtype=np.int64),
        )
        return np.maximum(
            prior_counts - np.asarray(self_history_flags, dtype=np.int64),
            0,
        )

    def _compute_recent_infra_burst_peers(
        self,
        indexed_events: list[tuple[int, AuthEvent]],
    ) -> np.ndarray:
        pair_codes: list[int] = []
        user_codes: list[int] = []
        timestamps: list[int] = []
        pair_encoder: dict[str, int] = {}
        user_encoder: dict[str, int] = {}
        next_pair_code = 1
        next_user_code = 1

        for _, event in indexed_events:
            pair_key = self._infrastructure_pair_key(event)
            if pair_key not in pair_encoder:
                pair_encoder[pair_key] = next_pair_code
                next_pair_code += 1
            if event.user_id not in user_encoder:
                user_encoder[event.user_id] = next_user_code
                next_user_code += 1
            pair_codes.append(pair_encoder[pair_key])
            user_codes.append(user_encoder[event.user_id])
            timestamps.append(int(event.timestamp.timestamp()))

        return shared_pair_recent_peer_counts(
            np.asarray(pair_codes, dtype=np.int64),
            np.asarray(user_codes, dtype=np.int64),
            np.asarray(timestamps, dtype=np.int64),
            window_seconds=max(int(self.relation_window.total_seconds()), 1),
        )

    def _compute_takeover_sequence_progress(
        self,
        indexed_events: list[tuple[int, AuthEvent]],
    ) -> np.ndarray:
        user_codes: list[int] = []
        stage_codes: list[int] = []
        timestamps: list[int] = []
        user_encoder: dict[str, int] = {}
        next_user_code = 1

        for _, event in indexed_events:
            if event.user_id not in user_encoder:
                user_encoder[event.user_id] = next_user_code
                next_user_code += 1
            user_codes.append(user_encoder[event.user_id])
            stage_codes.append(self._takeover_stage_code(event))
            timestamps.append(int(event.timestamp.timestamp()))

        raw_progress = ordered_takeover_sequence_progress(
            np.asarray(user_codes, dtype=np.int64),
            np.asarray(stage_codes, dtype=np.int64),
            np.asarray(timestamps, dtype=np.int64),
            window_seconds=max(int(self.relation_window.total_seconds()), 1),
        )
        return np.asarray(raw_progress, dtype=float) / 2.0

    def _takeover_stage_code(self, event: AuthEvent) -> int:
        if event.event_type == "privileged_action":
            return 3
        if event.event_type == "session_refresh" or event.auth_method == "token_refresh":
            return 2
        if event.event_type in {"login", "failed_login"}:
            return 1
        return 0

    def _infrastructure_pair_key(self, event: AuthEvent) -> str:
        if event.ip_address and event.asn:
            return f"ip_asn:{event.ip_address}|{event.asn}"
        if event.ip_address and event.device_fingerprint:
            return f"ip_device:{event.ip_address}|{event.device_fingerprint}"
        if event.device_fingerprint and event.asn:
            return f"device_asn:{event.device_fingerprint}|{event.asn}"
        if event.ip_address:
            return f"ip:{event.ip_address}"
        if event.device_fingerprint:
            return f"device:{event.device_fingerprint}"
        if event.asn:
            return f"asn:{event.asn}"
        return "missing"

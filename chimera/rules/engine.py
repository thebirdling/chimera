"""
Rule engine for Chimera.

Loads, validates, and evaluates deterministic threat-detection rules
against authentication events. Each rule produces RuleMatch objects
that are merged with ML anomaly scores for a unified risk picture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional, Callable
from collections import defaultdict
import logging

from chimera.data_loader import AuthEvent

logger = logging.getLogger(__name__)


# ── Data classes ─────────────────────────────────────────────────


@dataclass
class RuleDefinition:
    """Declarative definition of a detection rule."""

    id: str
    name: str
    description: str
    severity: str = "medium"  # low, medium, high, critical
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleMatch:
    """Result of a rule firing against one or more events."""

    rule_id: str
    rule_name: str
    severity: str
    description: str
    matched_events: list[int] = field(default_factory=list)  # event indices
    matched_users: list[str] = field(default_factory=list)
    timestamp: Optional[datetime] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "matched_events": self.matched_events,
            "matched_users": self.matched_users,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details,
        }


# ── Rule engine ──────────────────────────────────────────────────


class RuleEngine:
    """
    Evaluates a set of detection rules against authentication events.

    Usage::

        engine = RuleEngine()
        engine.load_builtin_rules()
        matches = engine.evaluate(events)
    """

    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}
        self._evaluators: dict[str, Callable] = {}

    # ── Registration ─────────────────────────────────────────────

    def register_rule(
        self,
        definition: RuleDefinition,
        evaluator: Callable[[list[AuthEvent], dict[str, Any]], list[RuleMatch]],
    ) -> None:
        """Register a rule with its evaluator function."""
        self._rules[definition.id] = definition
        self._evaluators[definition.id] = evaluator

    def load_builtin_rules(self) -> None:
        """Register all built-in rules shipped with Chimera."""
        _register_all_builtins(self)
        logger.info(f"Loaded {len(self._rules)} built-in rules")

    def list_rules(self) -> list[RuleDefinition]:
        """Return all registered rules."""
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> Optional[RuleDefinition]:
        return self._rules.get(rule_id)

    # ── Evaluation ───────────────────────────────────────────────

    def evaluate(self, events: list[AuthEvent]) -> list[RuleMatch]:
        """
        Evaluate all enabled rules against the event list.

        Args:
            events: List of AuthEvent objects (should be sorted by timestamp).

        Returns:
            List of RuleMatch objects for rules that fired.
        """
        all_matches: list[RuleMatch] = []

        for rule_id, rule_def in self._rules.items():
            if not rule_def.enabled:
                continue

            evaluator = self._evaluators.get(rule_id)
            if evaluator is None:
                continue

            try:
                matches = evaluator(events, rule_def.params)
                all_matches.extend(matches)
            except Exception as e:
                logger.warning(f"Rule '{rule_id}' evaluation failed: {e}")

        logger.info(
            f"Rule evaluation complete: {len(all_matches)} matches from "
            f"{len(self._rules)} rules"
        )
        return all_matches


# ── Built-in rule implementations ────────────────────────────────


def _eval_brute_force(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect brute-force login attempts: N failures in M minutes."""
    max_failures = params.get("max_failures", 5)
    window_minutes = params.get("window_minutes", 10)
    window = timedelta(minutes=window_minutes)

    matches = []
    user_failures: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)

    for idx, event in enumerate(events):
        if event.is_failure:
            user_failures[event.user_id].append((idx, event))

    for user_id, failures in user_failures.items():
        failures.sort(key=lambda x: x[1].timestamp)

        i = 0
        while i < len(failures):
            window_end = failures[i][1].timestamp + window
            burst = [f for f in failures[i:] if f[1].timestamp <= window_end]

            if len(burst) >= max_failures:
                matches.append(
                    RuleMatch(
                        rule_id="brute_force",
                        rule_name="Brute Force Attack",
                        severity="high",
                        description=(
                            f"{len(burst)} failed logins for {user_id} "
                            f"within {window_minutes} minutes"
                        ),
                        matched_events=[b[0] for b in burst],
                        matched_users=[user_id],
                        timestamp=burst[0][1].timestamp,
                        details={
                            "failure_count": len(burst),
                            "window_minutes": window_minutes,
                        },
                    )
                )
                i += len(burst)
            else:
                i += 1

    return matches


def _eval_impossible_travel(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect logins from different countries in an impossibly short time."""
    max_minutes = params.get("max_minutes", 60)
    window = timedelta(minutes=max_minutes)

    matches = []
    user_events: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)

    for idx, event in enumerate(events):
        if event.country_code:
            user_events[event.user_id].append((idx, event))

    for user_id, ue_list in user_events.items():
        ue_list.sort(key=lambda x: x[1].timestamp)

        for i in range(1, len(ue_list)):
            prev_idx, prev = ue_list[i - 1]
            curr_idx, curr = ue_list[i]

            time_diff = curr.timestamp - prev.timestamp
            if (
                time_diff <= window
                and prev.country_code != curr.country_code
                and time_diff.total_seconds() > 0
            ):
                matches.append(
                    RuleMatch(
                        rule_id="impossible_travel",
                        rule_name="Impossible Travel",
                        severity="critical",
                        description=(
                            f"{user_id} logged in from {prev.country_code} "
                            f"and {curr.country_code} within "
                            f"{int(time_diff.total_seconds() / 60)} minutes"
                        ),
                        matched_events=[prev_idx, curr_idx],
                        matched_users=[user_id],
                        timestamp=curr.timestamp,
                        details={
                            "from_country": prev.country_code,
                            "to_country": curr.country_code,
                            "time_diff_seconds": time_diff.total_seconds(),
                        },
                    )
                )

    return matches


def _eval_credential_stuffing(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect high-rate, multi-account login failures from the same IP."""
    min_users = params.get("min_users", 3)
    min_attempts = params.get("min_attempts", 6)
    window_minutes = params.get("window_minutes", 15)
    max_success_rate = params.get("max_success_rate", 0.2)
    window = timedelta(minutes=window_minutes)

    matches = []
    indexed_events = [
        (idx, e) for idx, e in enumerate(events) if e.ip_address and e.user_id
    ]

    ip_failures: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)
    for idx, e in indexed_events:
        ip_failures[e.ip_address].append((idx, e))

    for ip, ip_events in ip_failures.items():
        ip_events.sort(key=lambda x: x[1].timestamp)

        i = 0
        while i < len(ip_events):
            window_end = ip_events[i][1].timestamp + window
            burst = [f for f in ip_events[i:] if f[1].timestamp <= window_end]
            unique_users = {f[1].user_id for f in burst if f[1].user_id}
            failed_burst = [f for f in burst if f[1].is_failure]
            success_count = sum(1 for _, event in burst if event.success)
            success_rate = success_count / max(len(burst), 1)

            if (
                len(unique_users) >= min_users
                and len(failed_burst) >= min_attempts
                and success_rate <= max_success_rate
            ):
                matches.append(
                    RuleMatch(
                        rule_id="credential_stuffing",
                        rule_name="Credential Stuffing",
                        severity="critical",
                        description=(
                            f"{len(failed_burst)} login attempts across {len(unique_users)} accounts "
                            f"from IP {ip} within {window_minutes} minutes"
                        ),
                        matched_events=[b[0] for b in burst],
                        matched_users=sorted(unique_users),
                        timestamp=burst[0][1].timestamp,
                        details={
                            "ip_address": ip,
                            "unique_users": len(unique_users),
                            "attempt_count": len(burst),
                            "failed_attempt_count": len(failed_burst),
                            "success_rate": success_rate,
                        },
                    )
                )
                i += len(burst)
            else:
                i += 1

    return matches


def _eval_off_hours(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Flag logins outside typical business hours."""
    start_hour = params.get("start_hour", 6)
    end_hour = params.get("end_hour", 22)

    matches = []
    for idx, event in enumerate(events):
        hour = event.hour_of_day
        if hour < start_hour or hour >= end_hour:
            matches.append(
                RuleMatch(
                    rule_id="off_hours_login",
                    rule_name="Off-Hours Login",
                    severity="low",
                    description=(
                        f"{event.user_id} logged in at {hour:02d}:00 "
                        f"(outside {start_hour:02d}:00–{end_hour:02d}:00)"
                    ),
                    matched_events=[idx],
                    matched_users=[event.user_id],
                    timestamp=event.timestamp,
                    details={"hour": hour},
                )
            )

    return matches


def _eval_dormant_account(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect login to an account that has been inactive for a long time."""
    dormant_days = params.get("dormant_days", 30)

    matches = []
    user_last_seen: dict[str, tuple[int, AuthEvent]] = {}

    sorted_events = sorted(enumerate(events), key=lambda x: x[1].timestamp)

    for idx, event in sorted_events:
        if event.user_id in user_last_seen:
            last_idx, last_event = user_last_seen[event.user_id]
            gap = (event.timestamp - last_event.timestamp).days

            if gap >= dormant_days:
                matches.append(
                    RuleMatch(
                        rule_id="dormant_account",
                        rule_name="Dormant Account Login",
                        severity="medium",
                        description=(
                            f"{event.user_id} logged in after "
                            f"{gap} days of inactivity"
                        ),
                        matched_events=[idx],
                        matched_users=[event.user_id],
                        timestamp=event.timestamp,
                        details={"days_inactive": gap},
                    )
                )

        user_last_seen[event.user_id] = (idx, event)

    return matches


def _eval_new_device_new_location(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Flag events where the user has a new device AND a new location simultaneously."""
    matches = []
    user_known_devices: dict[str, set[str]] = defaultdict(set)
    user_known_countries: dict[str, set[str]] = defaultdict(set)

    sorted_events = sorted(enumerate(events), key=lambda x: x[1].timestamp)

    for idx, event in sorted_events:
        uid = event.user_id
        device = event.device_fingerprint or event.user_agent
        country = event.country_code

        if device and country:
            new_device = device not in user_known_devices[uid] and len(user_known_devices[uid]) > 0
            new_country = country not in user_known_countries[uid] and len(user_known_countries[uid]) > 0

            if new_device and new_country:
                matches.append(
                    RuleMatch(
                        rule_id="new_device_new_location",
                        rule_name="New Device + New Location",
                        severity="high",
                        description=(
                            f"{uid} logged in with a new device from "
                            f"new country {country}"
                        ),
                        matched_events=[idx],
                        matched_users=[uid],
                        timestamp=event.timestamp,
                        details={
                            "device": device[:64],
                            "country": country,
                        },
                    )
                )

        if device:
            user_known_devices[uid].add(device)
        if country:
            user_known_countries[uid].add(country)

    return matches


def _eval_mfa_bypass(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect a success without MFA after failures that used MFA."""
    matches = []
    user_recent: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)

    sorted_events = sorted(enumerate(events), key=lambda x: x[1].timestamp)

    for idx, event in sorted_events:
        uid = event.user_id
        user_recent[uid].append((idx, event))

        # Check: success without MFA after recent MFA failures
        if event.success and not event.mfa_used:
            recent = user_recent[uid][-10:]
            mfa_failures = [
                (i, e)
                for i, e in recent
                if e.is_failure and e.mfa_used and i != idx
            ]

            if len(mfa_failures) >= 2:
                matches.append(
                    RuleMatch(
                        rule_id="mfa_bypass",
                        rule_name="MFA Bypass Suspected",
                        severity="critical",
                        description=(
                            f"{uid} succeeded without MFA after "
                            f"{len(mfa_failures)} MFA failures"
                        ),
                        matched_events=[idx] + [i for i, _ in mfa_failures],
                        matched_users=[uid],
                        timestamp=event.timestamp,
                        details={"prior_mfa_failures": len(mfa_failures)},
                    )
                )

    return matches


def _eval_session_hijack(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect possible session hijacking: IP change mid-session."""
    matches = []
    session_ips: dict[str, tuple[str, int, AuthEvent]] = {}  # session_id → (ip, idx, event)

    sorted_events = sorted(enumerate(events), key=lambda x: x[1].timestamp)

    for idx, event in sorted_events:
        sid = event.session_id
        if not sid or not event.ip_address:
            continue

        if sid in session_ips:
            orig_ip, orig_idx, orig_event = session_ips[sid]
            if event.ip_address != orig_ip:
                matches.append(
                    RuleMatch(
                        rule_id="session_hijack",
                        rule_name="Session Hijack Suspected",
                        severity="critical",
                        description=(
                            f"Session {sid[:16]}... for {event.user_id} "
                            f"changed IP from {orig_ip} to {event.ip_address}"
                        ),
                        matched_events=[orig_idx, idx],
                        matched_users=[event.user_id],
                        timestamp=event.timestamp,
                        details={
                            "session_id": sid,
                            "original_ip": orig_ip,
                            "new_ip": event.ip_address,
                        },
                    )
                )
        else:
            session_ips[sid] = (event.ip_address, idx, event)

    return matches


def _eval_password_spraying(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect low-attempt cross-account failure bursts consistent with spraying."""
    min_users = params.get("min_users", 4)
    window_minutes = params.get("window_minutes", 45)
    per_user_max = params.get("per_user_max", 2)
    max_success_rate = params.get("max_success_rate", 0.15)
    window = timedelta(minutes=window_minutes)

    indexed_events = [
        (idx, e)
        for idx, e in enumerate(events)
        if e.ip_address and e.user_id
    ]
    grouped: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)
    for idx, event in indexed_events:
        grouped[event.ip_address].append((idx, event))

    matches = []
    for ip, ip_events in grouped.items():
        ip_events.sort(key=lambda item: item[1].timestamp)
        i = 0
        while i < len(ip_events):
            start_ts = ip_events[i][1].timestamp
            window_events = [
                item for item in ip_events[i:] if item[1].timestamp <= start_ts + window
            ]
            failed_events = [item for item in window_events if item[1].is_failure]
            unique_users = {event.user_id for _, event in failed_events}
            per_user_attempts: dict[str, int] = defaultdict(int)
            for _, event in failed_events:
                per_user_attempts[event.user_id] += 1
            success_rate = (
                sum(1 for _, event in window_events if event.success) / max(len(window_events), 1)
            )
            if (
                len(unique_users) >= min_users
                and failed_events
                and max(per_user_attempts.values(), default=0) <= per_user_max
                and success_rate <= max_success_rate
            ):
                matches.append(
                    RuleMatch(
                        rule_id="password_spraying",
                        rule_name="Password Spraying",
                        severity="critical",
                        description=(
                            f"{len(unique_users)} accounts saw low-attempt failures from IP {ip} "
                            f"within {window_minutes} minutes"
                        ),
                        matched_events=[idx for idx, _ in window_events],
                        matched_users=sorted(unique_users),
                        timestamp=window_events[0][1].timestamp,
                        details={
                            "ip_address": ip,
                            "unique_users": len(unique_users),
                            "failed_attempt_count": len(failed_events),
                            "max_attempts_per_user": max(per_user_attempts.values(), default=0),
                            "success_rate": success_rate,
                        },
                    )
                )
                i += len(window_events)
            else:
                i += 1

    return matches


def _eval_low_and_slow_campaign(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect low-rate cross-account failure campaigns spread across a longer window."""
    min_users = params.get("min_users", 3)
    min_failures = params.get("min_failures", 5)
    window_minutes = params.get("window_minutes", 180)
    min_span_minutes = params.get("min_span_minutes", 30)
    short_burst_minutes = params.get("short_burst_minutes", 15)
    short_burst_cap = params.get("short_burst_cap", 3)
    window = timedelta(minutes=window_minutes)
    short_window = timedelta(minutes=short_burst_minutes)

    indexed_events = [
        (idx, e)
        for idx, e in enumerate(events)
        if e.ip_address and e.user_id and e.is_failure
    ]
    grouped: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)
    for idx, event in indexed_events:
        grouped[event.ip_address].append((idx, event))

    matches = []
    for ip, ip_events in grouped.items():
        ip_events.sort(key=lambda item: item[1].timestamp)
        i = 0
        while i < len(ip_events):
            start_ts = ip_events[i][1].timestamp
            campaign = [item for item in ip_events[i:] if item[1].timestamp <= start_ts + window]
            if len(campaign) < min_failures:
                i += 1
                continue
            unique_users = {event.user_id for _, event in campaign}
            span_minutes = (
                campaign[-1][1].timestamp - campaign[0][1].timestamp
            ).total_seconds() / 60.0
            short_burst_max = 0
            for j in range(len(campaign)):
                burst_start = campaign[j][1].timestamp
                burst_count = sum(
                    1
                    for _, event in campaign[j:]
                    if event.timestamp <= burst_start + short_window
                )
                short_burst_max = max(short_burst_max, burst_count)
            if (
                len(unique_users) >= min_users
                and span_minutes >= min_span_minutes
                and short_burst_max <= short_burst_cap
            ):
                matches.append(
                    RuleMatch(
                        rule_id="low_and_slow_campaign",
                        rule_name="Low-and-Slow Campaign",
                        severity="high",
                        description=(
                            f"{len(campaign)} failed attempts across {len(unique_users)} accounts "
                            f"from IP {ip} over {span_minutes:.0f} minutes"
                        ),
                        matched_events=[idx for idx, _ in campaign],
                        matched_users=sorted(unique_users),
                        timestamp=campaign[0][1].timestamp,
                        details={
                            "ip_address": ip,
                            "unique_users": len(unique_users),
                            "failed_attempt_count": len(campaign),
                            "span_minutes": span_minutes,
                            "short_burst_max": short_burst_max,
                        },
                    )
                )
                i += len(campaign)
            else:
                i += 1

    return matches


def _eval_shared_infrastructure_burst(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect many users authenticating from the same IP+ASN in a short burst."""
    min_users = params.get("min_users", 3)
    window_minutes = params.get("window_minutes", 15)
    require_failures = params.get("require_failures", False)
    window = timedelta(minutes=window_minutes)

    indexed = [
        (idx, e)
        for idx, e in enumerate(events)
        if e.ip_address and e.asn and (not require_failures or e.is_failure)
    ]
    grouped: dict[tuple[str, str], list[tuple[int, AuthEvent]]] = defaultdict(list)
    for idx, event in indexed:
        grouped[(event.ip_address, event.asn)].append((idx, event))

    matches = []
    for (ip, asn), grouped_events in grouped.items():
        grouped_events.sort(key=lambda item: item[1].timestamp)
        i = 0
        while i < len(grouped_events):
            start_ts = grouped_events[i][1].timestamp
            burst = [
                item
                for item in grouped_events[i:]
                if item[1].timestamp <= start_ts + window
            ]
            unique_users = {event.user_id for _, event in burst}
            if len(unique_users) >= min_users:
                matches.append(
                    RuleMatch(
                        rule_id="shared_infrastructure_burst",
                        rule_name="Shared Infrastructure Burst",
                        severity="critical",
                        description=(
                            f"{len(unique_users)} users authenticated from IP {ip} "
                            f"and ASN {asn} within {window_minutes} minutes"
                        ),
                        matched_events=[idx for idx, _ in burst],
                        matched_users=sorted(unique_users),
                        timestamp=burst[0][1].timestamp,
                        details={
                            "ip_address": ip,
                            "asn": asn,
                            "unique_users": len(unique_users),
                        },
                    )
                )
                i += len(burst)
            else:
                i += 1

    return matches


def _eval_session_hijack_context(
    events: list[AuthEvent], params: dict[str, Any]
) -> list[RuleMatch]:
    """Detect possible session hijacking via IP or user-agent drift."""
    min_context_changes = params.get("min_context_changes", 1)
    matches = []
    session_state: dict[str, dict[str, Any]] = {}

    sorted_events = sorted(enumerate(events), key=lambda x: x[1].timestamp)

    for idx, event in sorted_events:
        sid = event.session_id
        if not sid:
            continue

        state = session_state.get(sid)
        if state is None:
            session_state[sid] = {
                "ip_address": event.ip_address,
                "user_agent": event.user_agent,
                "first_idx": idx,
                "change_count": 0,
            }
            continue

        context_changes = 0
        if event.ip_address and state.get("ip_address") and event.ip_address != state["ip_address"]:
            context_changes += 1
        if event.user_agent and state.get("user_agent") and event.user_agent != state["user_agent"]:
            context_changes += 1

        if context_changes:
            state["change_count"] = int(state.get("change_count", 0)) + context_changes
            if state["change_count"] >= min_context_changes:
                matches.append(
                    RuleMatch(
                        rule_id="session_hijack",
                        rule_name="Session Hijack Suspected",
                        severity="critical",
                        description=(
                            f"Session {sid[:16]}... for {event.user_id} "
                            "shifted identity context mid-session"
                        ),
                        matched_events=[state["first_idx"], idx],
                        matched_users=[event.user_id],
                        timestamp=event.timestamp,
                        details={
                            "session_id": sid,
                            "original_ip": state.get("ip_address"),
                            "new_ip": event.ip_address,
                            "original_user_agent": state.get("user_agent"),
                            "new_user_agent": event.user_agent,
                            "context_changes": state["change_count"],
                        },
                    )
                )

        if event.ip_address:
            state["ip_address"] = event.ip_address
        if event.user_agent:
            state["user_agent"] = event.user_agent

    return matches


# ── Registration helper ──────────────────────────────────────────


def _register_all_builtins(engine: RuleEngine) -> None:
    """Register all built-in rules into the engine."""
    _BUILTIN_RULES = [
        (
            RuleDefinition(
                id="brute_force",
                name="Brute Force Attack",
                description="Detects N+ failed logins within a short window",
                severity="high",
                tags=["authentication", "attack"],
                params={"max_failures": 5, "window_minutes": 10},
            ),
            _eval_brute_force,
        ),
        (
            RuleDefinition(
                id="impossible_travel",
                name="Impossible Travel",
                description="Detects logins from different countries in impossibly short time",
                severity="critical",
                tags=["geographic", "attack"],
                params={"max_minutes": 60},
            ),
            _eval_impossible_travel,
        ),
        (
            RuleDefinition(
                id="credential_stuffing",
                name="Credential Stuffing",
                description="High-rate multi-account failures from the same IP",
                severity="critical",
                tags=["authentication", "attack"],
                params={"min_users": 3, "min_attempts": 6, "window_minutes": 15, "max_success_rate": 0.2},
            ),
            _eval_credential_stuffing,
        ),
        (
            RuleDefinition(
                id="password_spraying",
                name="Password Spraying",
                description="Low-attempt cross-account failures from the same IP",
                severity="critical",
                tags=["authentication", "attack", "campaign"],
                params={"min_users": 4, "window_minutes": 45, "per_user_max": 2, "max_success_rate": 0.15},
            ),
            _eval_password_spraying,
        ),
        (
            RuleDefinition(
                id="low_and_slow_campaign",
                name="Low-and-Slow Campaign",
                description="Cross-account failures that accumulate slowly to avoid burst thresholds",
                severity="high",
                tags=["authentication", "attack", "campaign"],
                params={
                    "min_users": 3,
                    "min_failures": 5,
                    "window_minutes": 180,
                    "min_span_minutes": 30,
                    "short_burst_minutes": 15,
                    "short_burst_cap": 3,
                },
            ),
            _eval_low_and_slow_campaign,
        ),
        (
            RuleDefinition(
                id="off_hours_login",
                name="Off-Hours Login",
                description="Login outside typical business hours",
                severity="low",
                tags=["temporal", "policy"],
                params={"start_hour": 6, "end_hour": 22},
            ),
            _eval_off_hours,
        ),
        (
            RuleDefinition(
                id="dormant_account",
                name="Dormant Account Login",
                description="Login to an account inactive for N+ days",
                severity="medium",
                tags=["account", "risk"],
                params={"dormant_days": 30},
            ),
            _eval_dormant_account,
        ),
        (
            RuleDefinition(
                id="new_device_new_location",
                name="New Device + New Location",
                description="Simultaneous new device and new geo location",
                severity="high",
                tags=["device", "geographic"],
                params={},
            ),
            _eval_new_device_new_location,
        ),
        (
            RuleDefinition(
                id="mfa_bypass",
                name="MFA Bypass Suspected",
                description="Success without MFA after multiple MFA failures",
                severity="critical",
                tags=["authentication", "mfa"],
                params={},
            ),
            _eval_mfa_bypass,
        ),
        (
            RuleDefinition(
                id="session_hijack",
                name="Session Hijack Suspected",
                description="IP or user-agent drift during an active session",
                severity="critical",
                tags=["session", "attack"],
                params={"min_context_changes": 1},
            ),
            _eval_session_hijack_context,
        ),
        (
            RuleDefinition(
                id="shared_infrastructure_burst",
                name="Shared Infrastructure Burst",
                description="Many users authenticate from the same IP and ASN in a short window",
                severity="critical",
                tags=["authentication", "infrastructure", "attack"],
                params={"min_users": 3, "window_minutes": 15, "require_failures": False},
            ),
            _eval_shared_infrastructure_burst,
        ),
    ]

    for rule_def, evaluator in _BUILTIN_RULES:
        engine.register_rule(rule_def, evaluator)

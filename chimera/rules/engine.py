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
    """Detect many users failing from the same IP in a short window."""
    min_users = params.get("min_users", 3)
    window_minutes = params.get("window_minutes", 15)
    window = timedelta(minutes=window_minutes)

    matches = []
    failures = [
        (idx, e) for idx, e in enumerate(events) if e.is_failure and e.ip_address
    ]

    ip_failures: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)
    for idx, e in failures:
        ip_failures[e.ip_address].append((idx, e))

    for ip, ip_events in ip_failures.items():
        ip_events.sort(key=lambda x: x[1].timestamp)

        i = 0
        while i < len(ip_events):
            window_end = ip_events[i][1].timestamp + window
            burst = [f for f in ip_events[i:] if f[1].timestamp <= window_end]
            unique_users = set(f[1].user_id for f in burst)

            if len(unique_users) >= min_users:
                matches.append(
                    RuleMatch(
                        rule_id="credential_stuffing",
                        rule_name="Credential Stuffing",
                        severity="critical",
                        description=(
                            f"{len(unique_users)} users failed login from "
                            f"IP {ip} within {window_minutes} minutes"
                        ),
                        matched_events=[b[0] for b in burst],
                        matched_users=list(unique_users),
                        timestamp=burst[0][1].timestamp,
                        details={
                            "ip_address": ip,
                            "unique_users": len(unique_users),
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
                description="Many users failing from same IP in short window",
                severity="critical",
                tags=["authentication", "attack"],
                params={"min_users": 3, "window_minutes": 15},
            ),
            _eval_credential_stuffing,
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
                description="IP address change during active session",
                severity="critical",
                tags=["session", "attack"],
                params={},
            ),
            _eval_session_hijack,
        ),
    ]

    for rule_def, evaluator in _BUILTIN_RULES:
        engine.register_rule(rule_def, evaluator)

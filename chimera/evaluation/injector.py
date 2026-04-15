"""
chimera.evaluation.injector — Parameterized synthetic anomaly injection engine.

Overlays synthetic attack patterns onto a real event stream for evaluation.
Injected events are tagged with ``_synthetic: true`` and ``_injection_type``
for ground-truth evaluation (detection rate vs false positive rate).

Injection types
---------------
volume_spike          Multiply event count in a window by ``magnitude``.
temporal_shift        Shift timestamps to anomalous hours (e.g. 02:00–04:00 UTC).
credential_stuffing   Many failed logins across many distinct IPs from one user.
asn_shift             Replace source IPs with addresses from unusual ASN ranges.
burst_attack          Rapid-fire logins from a single IP within a short window.

All injection types are deterministic given the same ``seed``.
"""
from __future__ import annotations

import copy
import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

logger = logging.getLogger(__name__)

InjectionType = Literal[
    "volume_spike",
    "temporal_shift",
    "credential_stuffing",
    "asn_shift",
    "burst_attack",
    "session_hijack",
    "mfa_bypass",
    "low_and_slow",
    "password_spraying",
    "coordinated_campaign",
    "identity_drift",
    "temporal_jitter",
]

# Fake IP blocks to use for ASN shift (representative of unusual ranges)
_UNUSUAL_IP_BLOCKS = [
    "185.220.",   # Known Tor exit node range
    "45.142.",    # Common VPN/proxy range
    "91.108.",    # Telegram/unusual geo
    "198.144.",   # Hosting provider, unusual for human auth
    "194.165.",   # Eastern European hosting
]


def inject(
    events: list[dict],
    type: InjectionType,
    magnitude: float = 2.0,
    window: int = 50,
    seed: int = 42,
    target_users: Optional[list[str]] = None,
) -> list[dict]:
    """Overlay synthetic anomalies onto a real log stream.

    Parameters
    ----------
    events:
        Original authentication log events (list of dicts).
    type:
        The injection type. See module docstring.
    magnitude:
        Scaling factor for the injection intensity. Interpretation varies by type:
        - ``volume_spike``: multiply event count by ``magnitude``.
        - ``temporal_shift``: shift hour by ``magnitude`` (hours).
        - ``credential_stuffing``: ``magnitude`` unique IPs per injected event.
        - ``asn_shift``: fraction (0–1) of window events to replace.
        - ``burst_attack``: events per second (effective rate).
    window:
        Number of events (frame) in which to embed the injection.
    seed:
        Random seed for deterministic injection.
    target_users:
        If specified, only inject events for these user IDs.
        If None, a random user is selected.

    Returns
    -------
    list[dict]
        Original events plus injected events, sorted by timestamp.
        Injected events carry ``_synthetic: True`` and ``_injection_type`` fields.
    """
    rng = random.Random(seed)

    dispatchers: dict[str, callable] = {
        "volume_spike": _inject_volume_spike,
        "temporal_shift": _inject_temporal_shift,
        "credential_stuffing": _inject_credential_stuffing,
        "asn_shift": _inject_asn_shift,
        "burst_attack": _inject_burst_attack,
        "session_hijack": _inject_session_hijack,
        "mfa_bypass": _inject_mfa_bypass,
        "low_and_slow": _inject_low_and_slow,
        "password_spraying": _inject_password_spraying,
        "coordinated_campaign": _inject_coordinated_campaign,
        "identity_drift": _inject_identity_drift,
        "temporal_jitter": _inject_temporal_jitter,
    }

    if type not in dispatchers:
        raise ValueError(
            f"Unknown injection type {type!r}. "
            f"Valid types: {list(dispatchers.keys())}"
        )

    if not events:
        logger.warning("[injector] Event list is empty; nothing to inject.")
        return events

    # Select target user
    available_users = list({e.get("user_id", e.get("username", "unknown")) for e in events})
    if target_users:
        users = [u for u in target_users if u in available_users] or available_users
    else:
        users = available_users

    target_user = rng.choice(users)
    logger.info(
        "[injector] Injecting '%s' into user='%s' (magnitude=%.1f, window=%d, seed=%d)",
        type, target_user, magnitude, window, seed,
    )

    injected = dispatchers[type](
        events=events,
        target_user=target_user,
        magnitude=magnitude,
        window=window,
        rng=rng,
    )

    combined = events + injected
    # Sort by timestamp if available
    try:
        combined.sort(key=lambda e: e.get("timestamp", e.get("event_time", "")))
    except (TypeError, ValueError):
        pass  # timestamps not consistently sortable; leave original order

    logger.info("[injector] Injected %d synthetic events (total=%d)", len(injected), len(combined))
    return combined


# ------------------------------------------------------------------
# Injection strategy implementations
# ------------------------------------------------------------------

def _tag(event: dict, injection_type: str) -> dict:
    """Tag an event as synthetic."""
    e = copy.deepcopy(event)
    e["_synthetic"] = True
    e["_injection_type"] = injection_type
    return e


def _random_ip(rng: random.Random, block: Optional[str] = None) -> str:
    """Generate a random IP address, optionally within a block prefix."""
    if block:
        return f"{block}{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    return f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _timestamp_key(event: dict) -> str:
    return "timestamp" if "timestamp" in event else "event_time"


def _parse_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return datetime.now(tz=timezone.utc)


def _set_timestamp(event: dict, dt: datetime) -> None:
    event[_timestamp_key(event)] = dt.isoformat()


def _user_events(events: list[dict], user_id: str) -> list[dict]:
    user_events = [
        e for e in events if e.get("user_id", e.get("username")) == user_id
    ]
    try:
        return sorted(
            user_events,
            key=lambda e: _parse_timestamp(e.get("timestamp", e.get("event_time"))),
        )
    except Exception:
        return user_events


def _session_window(
    user_events: list[dict],
    window: int,
    rng: random.Random,
) -> list[dict]:
    if not user_events:
        return []
    take = min(len(user_events), max(3, window))
    if len(user_events) <= take:
        return list(user_events)
    start = rng.randint(0, len(user_events) - take)
    return user_events[start : start + take]


def _inject_volume_spike(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    """Duplicate events for target_user ``ceil(magnitude)`` times within a window."""
    user_events = [
        e for e in events
        if e.get("user_id", e.get("username")) == target_user
    ]
    if not user_events:
        return []

    sample = rng.choices(user_events, k=min(window, len(user_events)))
    n_inject = int(len(sample) * max(1.0, magnitude))
    result = []
    for i in range(n_inject):
        base = rng.choice(sample)
        ev = _tag(base, "volume_spike")
        result.append(ev)
    return result


def _inject_temporal_shift(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    """Shift event timestamps to anomalous hours (2–4 AM UTC by default)."""
    user_events = [
        e for e in events
        if e.get("user_id", e.get("username")) == target_user
    ][:window]

    result = []
    for base in user_events:
        ev = _tag(base, "temporal_shift")
        # Attempt to parse and shift timestamp
        ts = ev.get("timestamp", ev.get("event_time", ""))
        if ts:
            try:
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                elif isinstance(ts, (int, float)):
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                else:
                    dt = ts
                # Shift to early morning (anomalous window)
                anomalous_hour = int(magnitude) % 24
                dt_shifted = dt.replace(hour=anomalous_hour, minute=rng.randint(0, 59))
                ts_key = "timestamp" if "timestamp" in ev else "event_time"
                ev[ts_key] = dt_shifted.isoformat()
            except (ValueError, AttributeError, TypeError):
                pass  # leave timestamp unchanged if unparseable
        result.append(ev)
    return result


def _inject_credential_stuffing(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    """Generate failed logins from a large number of distinct IPs."""
    user_events = [
        e for e in events
        if e.get("user_id", e.get("username")) == target_user
    ]
    if not user_events:
        return []

    base = rng.choice(user_events)
    n_inject = max(window, int(magnitude * 10))
    result = []
    for _ in range(n_inject):
        ev = _tag(base, "credential_stuffing")
        ev["source_ip"] = _random_ip(rng)
        ev["ip_address"] = ev["source_ip"]
        ev["outcome"] = "failure"
        ev["status"] = "FAILED_AUTHENTICATION"
        ev["event_type"] = "failed_login"
        ev["success"] = False
        result.append(ev)
    return result


def _inject_asn_shift(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    """Replace source IPs with addresses from unusual ASN blocks."""
    user_events = [
        e for e in events
        if e.get("user_id", e.get("username")) == target_user
    ][:window]

    # Fraction of events to replace (magnitude 1.0 = 50%, 2.0 = 100%)
    fraction = min(1.0, magnitude / 2.0)
    n_replace = max(1, int(len(user_events) * fraction))
    result = []
    for i, base in enumerate(user_events):
        ev = _tag(base, "asn_shift")
        if i < n_replace:
            block = rng.choice(_UNUSUAL_IP_BLOCKS)
            ev["source_ip"] = _random_ip(rng, block=block)
            ev["ip_address"] = ev["source_ip"]
            ev["asn"] = f"ASN-{rng.randint(64000, 64511)}"
        result.append(ev)
    return result


def _inject_burst_attack(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    """Rapid-fire logins from a single IP within an extremely short time window."""
    user_events = [
        e for e in events
        if e.get("user_id", e.get("username")) == target_user
    ]
    if not user_events:
        return []

    base = rng.choice(user_events)
    attacker_ip = _random_ip(rng, block=rng.choice(_UNUSUAL_IP_BLOCKS))
    n_inject = max(10, int(window * magnitude))

    # Create a burst of events within a 60-second window
    try:
        ts_raw = base.get("timestamp", base.get("event_time", ""))
        if isinstance(ts_raw, str):
            burst_start = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        else:
            burst_start = datetime.now(tz=timezone.utc)
    except (ValueError, AttributeError, TypeError):
        burst_start = datetime.now(tz=timezone.utc)

    result = []
    for i in range(n_inject):
        ev = _tag(base, "burst_attack")
        ev["source_ip"] = attacker_ip
        ev["ip_address"] = attacker_ip
        offset_seconds = (i / max(n_inject - 1, 1)) * 60.0  # spread over 60s
        ts_key = "timestamp" if "timestamp" in ev else "event_time"
        ev[ts_key] = (burst_start + timedelta(seconds=offset_seconds)).isoformat()
        result.append(ev)
    return result


def _inject_session_hijack(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    user_events = _session_window(_user_events(events, target_user), max(window, 5), rng)
    if not user_events:
        return []

    base = user_events[min(len(user_events) - 1, max(0, len(user_events) // 2))]
    anchor_ts = _parse_timestamp(base.get("timestamp", base.get("event_time")))
    attacker_ip = _random_ip(rng, block=rng.choice(_UNUSUAL_IP_BLOCKS))
    victim_ip = base.get("ip_address") or base.get("source_ip") or _random_ip(rng)
    victim_ua = base.get("user_agent") or "Mozilla/5.0"
    attacker_ua = rng.choice(
        [
            "python-requests/2.31",
            "curl/8.7.1",
            "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/122.0",
        ]
    )
    hijacked_device = f"hijacked-{rng.randint(1000, 9999)}"
    attacker_country = rng.choice(["RU", "NL", "SG"])
    attacker_asn = f"ASN-{rng.randint(64000, 64511)}"
    n_refresh = max(6, int(8 * magnitude))
    result = []
    shared_session_id = f"hijack-{target_user}"

    # First, create overlapping victim-side refreshes to simulate a still-active real session.
    for i in range(max(3, int(magnitude) + 1)):
        ev = _tag(base, "session_hijack")
        ev["ip_address"] = victim_ip
        ev["source_ip"] = victim_ip
        ev["user_agent"] = victim_ua
        ev["device_fingerprint"] = base.get("device_fingerprint") or f"victim-dev-{rng.randint(10,99)}"
        ev["country_code"] = base.get("country_code") or "NG"
        ev["asn"] = base.get("asn") or "ASN-64512"
        ev["auth_method"] = "token_refresh"
        ev["event_type"] = "session_refresh"
        ev["success"] = True
        ev["mfa_used"] = True
        ev["session_id"] = shared_session_id
        ev["outcome"] = "success"
        _set_timestamp(ev, anchor_ts + timedelta(minutes=1, seconds=i * 4))
        result.append(ev)

    for i in range(n_refresh):
        ev = _tag(base, "session_hijack")
        ev["ip_address"] = attacker_ip
        ev["source_ip"] = attacker_ip
        ev["user_agent"] = attacker_ua
        ev["device_fingerprint"] = hijacked_device
        ev["country_code"] = attacker_country
        ev["asn"] = attacker_asn
        ev["auth_method"] = "token_refresh" if i else "password"
        ev["event_type"] = "session_refresh" if i else "login"
        ev["success"] = True
        ev["mfa_used"] = False
        ev["session_id"] = shared_session_id
        ev["outcome"] = "success"
        _set_timestamp(ev, anchor_ts + timedelta(minutes=1, seconds=2 + i * 3))
        ev["raw_fields"] = dict(ev.get("raw_fields", {}), token_hash=f"tok-{shared_session_id}")
        result.append(ev)

    # Add a replay-style burst from the stolen session context.
    for i in range(max(8, int(10 * magnitude))):
        ev = _tag(base, "session_hijack")
        ev["ip_address"] = attacker_ip
        ev["source_ip"] = attacker_ip
        ev["user_agent"] = attacker_ua
        ev["device_fingerprint"] = hijacked_device
        ev["country_code"] = attacker_country
        ev["asn"] = attacker_asn
        ev["auth_method"] = "token_refresh"
        ev["event_type"] = "session_refresh"
        ev["success"] = True
        ev["mfa_used"] = False
        ev["session_id"] = shared_session_id
        ev["outcome"] = "success"
        _set_timestamp(ev, anchor_ts + timedelta(minutes=2, seconds=i % 5))
        ev["raw_fields"] = dict(ev.get("raw_fields", {}), token_hash=f"tok-{shared_session_id}")
        result.append(ev)

    # Add a short post-compromise fan-out phase from the same infrastructure.
    for i in range(max(2, int(magnitude) + 1)):
        ev = _tag(base, "session_hijack")
        ev["ip_address"] = attacker_ip
        ev["source_ip"] = attacker_ip
        ev["user_agent"] = attacker_ua
        ev["device_fingerprint"] = hijacked_device
        ev["country_code"] = attacker_country
        ev["asn"] = attacker_asn
        ev["auth_method"] = "api_key"
        ev["event_type"] = "privileged_action"
        ev["success"] = True
        ev["mfa_used"] = False
        ev["session_id"] = shared_session_id
        _set_timestamp(ev, anchor_ts + timedelta(minutes=4 + i))
        ev["raw_fields"] = dict(ev.get("raw_fields", {}), token_hash=f"tok-{shared_session_id}")
        result.append(ev)
    return result


def _inject_mfa_bypass(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    user_events = _session_window(_user_events(events, target_user), max(window, 4), rng)
    if not user_events:
        return []

    base = user_events[min(len(user_events) - 1, max(0, len(user_events) // 2))]
    anchor_ts = _parse_timestamp(base.get("timestamp", base.get("event_time")))
    attacker_ip = _random_ip(rng, block=rng.choice(_UNUSUAL_IP_BLOCKS))
    attacker_device = f"mfa-bypass-{rng.randint(100, 999)}"
    result = []

    for i in range(max(2, int(magnitude))):
        ev = _tag(base, "mfa_bypass")
        ev["event_type"] = "mfa_failure"
        ev["success"] = False
        ev["mfa_used"] = True
        ev["auth_method"] = "mfa"
        ev["failure_reason"] = "otp_invalid"
        ev["outcome"] = "failure"
        ev["ip_address"] = attacker_ip
        ev["source_ip"] = attacker_ip
        ev["device_fingerprint"] = attacker_device
        _set_timestamp(ev, anchor_ts + timedelta(minutes=i * 2))
        result.append(ev)

    success = _tag(base, "mfa_bypass")
    success["event_type"] = "login"
    success["success"] = True
    success["mfa_used"] = False
    success["auth_method"] = "password"
    success["outcome"] = "success"
    success["ip_address"] = attacker_ip
    success["source_ip"] = attacker_ip
    success["device_fingerprint"] = attacker_device
    success["country_code"] = rng.choice(["NL", "RU", "SG"])
    success["asn"] = f"ASN-{rng.randint(64000, 64511)}"
    _set_timestamp(success, anchor_ts + timedelta(minutes=max(2, int(magnitude)) * 2 + 1))
    result.append(success)
    return result


def _inject_low_and_slow(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    user_events = _session_window(_user_events(events, target_user), max(window, 6), rng)
    if not user_events:
        return []

    base = rng.choice(user_events)
    start = _parse_timestamp(base.get("timestamp", base.get("event_time")))
    attacker_ips = [
        _random_ip(rng, block=rng.choice(_UNUSUAL_IP_BLOCKS))
        for _ in range(2)
    ]
    result = []
    for i in range(max(6, int(8 * magnitude))):
        ev = _tag(base, "low_and_slow")
        _set_timestamp(ev, start + timedelta(hours=i * 6 + rng.randint(0, 2)))
        ev["country_code"] = rng.choice(["NL", "DE", "US", "GB"])
        ev["ip_address"] = attacker_ips[i % len(attacker_ips)]
        ev["source_ip"] = ev["ip_address"]
        ev["device_fingerprint"] = f"slow-drift-{i % 2}"
        ev["asn"] = f"ASN-{64490 + (i % 3)}"
        ev["auth_method"] = "password"
        ev["success"] = True
        result.append(ev)
    return result


def _inject_password_spraying(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    target_pool = sorted({e.get("user_id", e.get("username", "unknown")) for e in events})
    target_pool = target_pool[: max(3, min(len(target_pool), int(4 * magnitude) + 2))]
    base = copy.deepcopy(events[0])
    attacker_ip = _random_ip(rng, block=rng.choice(_UNUSUAL_IP_BLOCKS))
    start = _parse_timestamp(base.get("timestamp", base.get("event_time")))
    result = []
    for i, user_id in enumerate(target_pool):
        ev = _tag(base, "password_spraying")
        ev["user_id"] = user_id
        ev["ip_address"] = attacker_ip
        ev["source_ip"] = attacker_ip
        ev["device_fingerprint"] = "spray-device"
        ev["country_code"] = "RU"
        ev["event_type"] = "failed_login"
        ev["success"] = False
        ev["outcome"] = "failure"
        ev["asn"] = "ASN-64496"
        ev["mfa_used"] = False
        _set_timestamp(ev, start + timedelta(seconds=i * 45))
        result.append(ev)
    return result


def _inject_coordinated_campaign(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    users = sorted({e.get("user_id", e.get("username", "unknown")) for e in events})
    if not users:
        return []
    attack_users = users[: max(3, min(len(users), int(5 * magnitude)))]
    base = copy.deepcopy(events[0])
    shared_ips = [
        _random_ip(rng, block=rng.choice(_UNUSUAL_IP_BLOCKS))
        for _ in range(2)
    ]
    shared_device = f"campaign-device-{rng.randint(10, 99)}"
    base_ts = _parse_timestamp(base.get("timestamp", base.get("event_time")))
    result = []
    for i, user_id in enumerate(attack_users):
        for phase in range(2):
            ev = _tag(base, "coordinated_campaign")
            ev["user_id"] = user_id
            ev["ip_address"] = shared_ips[phase % len(shared_ips)]
            ev["source_ip"] = ev["ip_address"]
            ev["device_fingerprint"] = shared_device
            ev["country_code"] = "NL"
            ev["asn"] = "ASN-64496"
            ev["auth_method"] = "password"
            ev["event_type"] = "failed_login" if phase == 0 else "login"
            ev["success"] = phase != 0
            ev["outcome"] = "failure" if phase == 0 else "success"
            _set_timestamp(
                ev,
                base_ts + timedelta(minutes=i, seconds=phase * 35 + rng.randint(0, 8)),
            )
            result.append(ev)
    return result


def _inject_identity_drift(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    user_events = _session_window(_user_events(events, target_user), max(window, 5), rng)
    if not user_events:
        return []
    result = []
    drift_countries = ["US", "SG", "BR", "ZA", "JP"]
    drift_devices = [f"drift-{i}" for i in range(1, 6)]
    for i, base in enumerate(user_events):
        ev = _tag(base, "identity_drift")
        ev["country_code"] = drift_countries[i % len(drift_countries)]
        ev["device_fingerprint"] = drift_devices[i % len(drift_devices)]
        ev["auth_method"] = "api_key" if i % 2 else "password"
        ev["ip_address"] = _random_ip(rng, block=rng.choice(_UNUSUAL_IP_BLOCKS))
        ev["source_ip"] = ev["ip_address"]
        ev["asn"] = f"ASN-{64480 + (i % 10)}"
        ev["success"] = True
        result.append(ev)
    return result


def _inject_temporal_jitter(
    events: list[dict], target_user: str, magnitude: float, window: int, rng: random.Random
) -> list[dict]:
    user_events = _session_window(_user_events(events, target_user), max(window, 8), rng)
    if not user_events:
        return []
    result = []
    jitter_band = max(300, int(1800 * max(magnitude, 1.0)))
    for i, base in enumerate(user_events):
        ev = _tag(base, "temporal_jitter")
        ts = _parse_timestamp(base.get("timestamp", base.get("event_time")))
        direction = -1 if i % 2 else 1
        jitter = rng.randint(90, jitter_band)
        _set_timestamp(ev, ts + timedelta(seconds=direction * jitter))
        ev["ip_address"] = _random_ip(rng, block=rng.choice(_UNUSUAL_IP_BLOCKS))
        ev["source_ip"] = ev["ip_address"]
        ev["device_fingerprint"] = f"jitter-device-{i % 3}"
        result.append(ev)
    return result

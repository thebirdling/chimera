#!/usr/bin/env python3
"""
Generate synthetic authentication logs for testing Chimera.

Supports realistic user profiles and attack scenario generation
including brute force, impossible travel, credential stuffing,
and insider threat patterns.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path


# ── User profile templates ───────────────────────────────────────

OFFICE_HOURS = list(range(7, 19))
NIGHT_HOURS = list(range(0, 6)) + list(range(22, 24))
ALL_HOURS = list(range(0, 24))

COUNTRIES = ["US", "GB", "DE", "FR", "CA", "AU", "JP", "BR", "IN", "NL"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/17.0",
]
ASN_LIST = ["AS15169", "AS13335", "AS16509", "AS8075", "AS14618", "AS20940"]
AUTH_METHODS = ["password", "sso", "mfa", "certificate", "biometric"]

EVENT_TYPES = ["login_success", "login_failed", "mfa_success", "mfa_failure", "logout"]


def _random_ip() -> str:
    return f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _generate_user_profile(user_id: str) -> dict:
    """Create a realistic user profile with typical patterns."""
    home_country = random.choice(COUNTRIES[:5])
    typical_hours = random.choice([OFFICE_HOURS, ALL_HOURS])
    n_ips = random.randint(1, 3)
    n_devices = random.randint(1, 2)

    return {
        "user_id": user_id,
        "home_country": home_country,
        "typical_hours": typical_hours,
        "ips": [_random_ip() for _ in range(n_ips)],
        "user_agents": random.sample(USER_AGENTS, n_devices),
        "asn": random.choice(ASN_LIST),
        "auth_method": random.choice(AUTH_METHODS[:3]),
        "failure_rate": random.uniform(0.02, 0.10),
    }


def _generate_normal_event(
    profile: dict, base_time: datetime, offset_hours: float
) -> dict:
    """Generate a normal authentication event for a user."""
    ts = base_time + timedelta(hours=offset_hours)
    hour = random.choice(profile["typical_hours"])
    ts = ts.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

    is_failure = random.random() < profile["failure_rate"]
    event_type = "login_failed" if is_failure else "login_success"

    if not is_failure and random.random() < 0.3:
        event_type = "mfa_success"

    return {
        "timestamp": ts.isoformat(),
        "user_id": profile["user_id"],
        "event_type": event_type,
        "ip_address": random.choice(profile["ips"]),
        "user_agent": random.choice(profile["user_agents"]),
        "country_code": profile["home_country"],
        "asn": profile["asn"],
        "auth_method": profile["auth_method"],
        "success": not is_failure,
        "mfa_used": "mfa" in event_type or random.random() < 0.4,
        "session_id": str(uuid.uuid4()),
        "session_duration_seconds": random.randint(60, 28800) if not is_failure else 0,
        "device_fingerprint": profile["user_agents"][0][:32],
    }


# ── Attack scenario generators ───────────────────────────────────


def _generate_brute_force(
    target_user: str, base_time: datetime, count: int = 20
) -> list[dict]:
    """Generate brute-force attack events."""
    attacker_ip = _random_ip()
    events = []
    ts = base_time

    for i in range(count):
        ts += timedelta(seconds=random.randint(2, 30))
        events.append({
            "timestamp": ts.isoformat(),
            "user_id": target_user,
            "event_type": "login_failed" if i < count - 1 else "login_success",
            "ip_address": attacker_ip,
            "user_agent": "Mozilla/5.0 (compatible; BruteBot/1.0)",
            "country_code": random.choice(COUNTRIES[5:]),
            "asn": random.choice(ASN_LIST[3:]),
            "auth_method": "password",
            "success": i == count - 1,
            "mfa_used": False,
            "session_id": str(uuid.uuid4()),
            "session_duration_seconds": 0 if i < count - 1 else random.randint(10, 60),
            "device_fingerprint": "bruteforcedevice",
        })

    return events


def _generate_impossible_travel(
    user_id: str, base_time: datetime
) -> list[dict]:
    """Generate impossible-travel scenario."""
    events = []
    ts = base_time

    # Login from US
    events.append({
        "timestamp": ts.isoformat(),
        "user_id": user_id,
        "event_type": "login_success",
        "ip_address": _random_ip(),
        "user_agent": random.choice(USER_AGENTS),
        "country_code": "US",
        "asn": "AS15169",
        "auth_method": "password",
        "success": True,
        "mfa_used": True,
        "session_id": str(uuid.uuid4()),
        "session_duration_seconds": random.randint(300, 3600),
        "device_fingerprint": "normaldevice1",
    })

    # Login from Russia 15 minutes later
    ts += timedelta(minutes=15)
    events.append({
        "timestamp": ts.isoformat(),
        "user_id": user_id,
        "event_type": "login_success",
        "ip_address": _random_ip(),
        "user_agent": random.choice(USER_AGENTS),
        "country_code": "RU",
        "asn": "AS12389",
        "auth_method": "password",
        "success": True,
        "mfa_used": False,
        "session_id": str(uuid.uuid4()),
        "session_duration_seconds": random.randint(60, 600),
        "device_fingerprint": "suspiciousdevice",
    })

    return events


def _generate_credential_stuffing(
    users: list[str], base_time: datetime
) -> list[dict]:
    """Generate credential-stuffing attack from a single IP."""
    attacker_ip = _random_ip()
    events = []
    ts = base_time

    for user_id in users[:min(len(users), 10)]:
        ts += timedelta(seconds=random.randint(1, 10))
        events.append({
            "timestamp": ts.isoformat(),
            "user_id": user_id,
            "event_type": "login_failed",
            "ip_address": attacker_ip,
            "user_agent": "python-requests/2.28.0",
            "country_code": random.choice(COUNTRIES[5:]),
            "asn": random.choice(ASN_LIST[3:]),
            "auth_method": "password",
            "success": False,
            "mfa_used": False,
            "session_id": str(uuid.uuid4()),
            "session_duration_seconds": 0,
            "device_fingerprint": "stuffbot",
        })

    return events


def _generate_insider_threat(
    user_id: str, base_time: datetime, days: int = 3
) -> list[dict]:
    """Generate insider-threat pattern: off-hours, bulk access."""
    events = []

    for day in range(days):
        ts = base_time + timedelta(days=day)
        # Late night access
        for _ in range(random.randint(5, 15)):
            hour = random.choice([1, 2, 3, 4, 23])
            event_ts = ts.replace(
                hour=hour,
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
            )
            events.append({
                "timestamp": event_ts.isoformat(),
                "user_id": user_id,
                "event_type": "login_success",
                "ip_address": _random_ip(),
                "user_agent": random.choice(USER_AGENTS),
                "country_code": "US",
                "asn": random.choice(ASN_LIST),
                "auth_method": "password",
                "success": True,
                "mfa_used": False,
                "session_id": str(uuid.uuid4()),
                "session_duration_seconds": random.randint(3600, 14400),
                "device_fingerprint": "insiderdevice",
            })

    return events


# ── Main generator ───────────────────────────────────────────────


def generate_data(
    n_users: int = 15,
    n_events: int = 300,
    scenario: str = "mixed",
    days: int = 7,
    seed: int = 42,
) -> list[dict]:
    """
    Generate synthetic authentication log data.

    Args:
        n_users: Number of user profiles to create.
        n_events: Approximate number of normal events per user.
        scenario: Attack scenario to inject ("mixed", "brute_force",
                  "impossible_travel", "credential_stuffing", "insider", "none").
        days: Number of days to span.
        seed: Random seed for reproducibility.

    Returns:
        List of event dictionaries.
    """
    random.seed(seed)
    base_time = datetime(2025, 1, 15, 0, 0, 0)

    # Create user profiles
    user_ids = [f"user_{i:03d}" for i in range(n_users)]
    profiles = {uid: _generate_user_profile(uid) for uid in user_ids}

    # Generate normal events
    events = []
    for uid, profile in profiles.items():
        n_user_events = max(5, n_events // n_users + random.randint(-5, 5))
        for _ in range(n_user_events):
            offset = random.uniform(0, days * 24)
            events.append(_generate_normal_event(profile, base_time, offset))

    # Inject attack scenarios
    attack_time = base_time + timedelta(days=days // 2)

    if scenario in ("mixed", "brute_force"):
        target = random.choice(user_ids)
        events.extend(_generate_brute_force(target, attack_time))

    if scenario in ("mixed", "impossible_travel"):
        target = random.choice(user_ids)
        events.extend(_generate_impossible_travel(target, attack_time + timedelta(hours=3)))

    if scenario in ("mixed", "credential_stuffing"):
        events.extend(
            _generate_credential_stuffing(
                random.sample(user_ids, min(8, n_users)),
                attack_time + timedelta(hours=6),
            )
        )

    if scenario in ("mixed", "insider"):
        target = random.choice(user_ids)
        events.extend(_generate_insider_threat(target, attack_time))

    # Sort by timestamp
    events.sort(key=lambda e: e["timestamp"])
    return events


def write_csv(events: list[dict], path: str) -> None:
    """Write events to CSV file."""
    if not events:
        return
    fieldnames = list(events[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)


def write_json(events: list[dict], path: str) -> None:
    """Write events to JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic authentication logs for Chimera testing"
    )
    parser.add_argument(
        "-o", "--output",
        default="sample_auth_logs.csv",
        help="Output file path (supports .csv and .json)",
    )
    parser.add_argument(
        "--users", type=int, default=15,
        help="Number of users to simulate (default: 15)",
    )
    parser.add_argument(
        "--events", type=int, default=300,
        help="Approximate number of events (default: 300)",
    )
    parser.add_argument(
        "--scenario",
        choices=["mixed", "brute_force", "impossible_travel", "credential_stuffing", "insider", "none"],
        default="mixed",
        help="Attack scenario to inject (default: mixed)",
    )
    parser.add_argument(
        "--days", type=int, default=7,
        help="Number of days to span (default: 7)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed (default: 42)",
    )

    args = parser.parse_args()
    
    # Use ASCII for Windows compatibility
    print(f"[+] Generating data: {args.users} users, ~{args.events} events, scenario={args.scenario}")
    events = generate_data(
        n_users=args.users,
        n_events=args.events,
        scenario=args.scenario,
        days=args.days,
        seed=args.seed,
    )

    output_path = Path(args.output)
    if output_path.suffix == ".json":
        write_json(events, str(output_path))
    else:
        write_csv(events, str(output_path))
        
    print(f"[+] Generated {len(events)} events -> {output_path}")


if __name__ == "__main__":
    main()

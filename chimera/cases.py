"""
Deterministic case-level identity reasoning for Chimera v0.6.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha1
from typing import Any, Optional

import pandas as pd

from chimera.data_loader import AuthEvent
from chimera.scoring import AnomalyResult


@dataclass
class IdentityCase:
    """Deterministic grouping of related identity anomalies."""

    case_id: str
    case_type: str
    severity: str
    confidence_band: str
    score: float
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    involved_users: list[str] = field(default_factory=list)
    involved_sessions: list[str] = field(default_factory=list)
    involved_ips: list[str] = field(default_factory=list)
    involved_devices: list[str] = field(default_factory=list)
    involved_asns: list[str] = field(default_factory=list)
    representative_event_indices: list[int] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_type": self.case_type,
            "severity": self.severity,
            "confidence_band": self.confidence_band,
            "score": round(float(self.score), 4),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "involved_users": self.involved_users,
            "involved_sessions": self.involved_sessions,
            "involved_ips": self.involved_ips,
            "involved_devices": self.involved_devices,
            "involved_asns": self.involved_asns,
            "representative_event_indices": self.representative_event_indices,
            "reasons": self.reasons,
        }


def aggregate_identity_cases(
    results: list[AnomalyResult],
    *,
    features_df: Optional[pd.DataFrame] = None,
    case_time_window_minutes: int = 30,
) -> list[IdentityCase]:
    """Group anomalous events into deterministic case objects."""
    if not results:
        return []

    features_df = features_df if features_df is not None else pd.DataFrame()
    enriched: list[dict[str, Any]] = []
    for result in results:
        event = result.raw_event
        if event is None:
            event = AuthEvent(
                timestamp=result.timestamp,
                user_id=result.user_id,
                event_type=result.event_type,
            )
        signals = result.research_signals
        enriched.append(
            {
                "result": result,
                "event": event,
                "takeover_score": float(signals.get("identity_takeover_score", 0.0)),
                "sequence_score": float(signals.get("identity_takeover_sequence_score", 0.0)),
                "campaign_score": float(signals.get("identity_campaign_score", 0.0)),
                "spray_score": float(signals.get("identity_password_spray_score", 0.0)),
                "low_and_slow_score": float(signals.get("identity_low_and_slow_score", 0.0)),
                "relationship_score": float(signals.get("identity_relationship_score", 0.0)),
            }
        )

    cases: list[IdentityCase] = []
    cases.extend(
        _build_cases(
            case_type="session_takeover_case",
            candidates=[
                item for item in enriched
                if item["result"].is_anomaly
                and (
                    item["takeover_score"] >= 0.58
                    or item["sequence_score"] >= 0.5
                )
            ],
            key_fn=lambda item: (
                item["event"].user_id,
                item["event"].session_id or item["event"].ip_address or "no-session",
            ),
            case_time_window_minutes=case_time_window_minutes,
        )
    )
    cases.extend(
        _build_cases(
            case_type="password_spray_case",
            candidates=[
                item for item in enriched
                if item["spray_score"] >= 0.5
            ],
            key_fn=lambda item: (
                item["event"].ip_address or "no-ip",
                item["event"].asn or "no-asn",
            ),
            case_time_window_minutes=case_time_window_minutes,
        )
    )
    cases.extend(
        _build_cases(
            case_type="low_and_slow_campaign_case",
            candidates=[
                item for item in enriched
                if item["low_and_slow_score"] >= 0.5
            ],
            key_fn=lambda item: (
                item["event"].ip_address or "no-ip",
                item["event"].asn or "no-asn",
            ),
            case_time_window_minutes=max(case_time_window_minutes, 180),
        )
    )
    cases.extend(
        _build_cases(
            case_type="coordinated_identity_campaign_case",
            candidates=[
                item for item in enriched
                if item["campaign_score"] >= 0.55
                or item["relationship_score"] >= 0.55
            ],
            key_fn=lambda item: (
                item["event"].ip_address or "no-ip",
                item["event"].device_fingerprint or item["event"].user_agent or "no-device",
                item["event"].asn or "no-asn",
            ),
            case_time_window_minutes=case_time_window_minutes,
            require_multi_user=True,
        )
    )
    return sorted(cases, key=lambda case: (case.first_seen or datetime.min, case.case_type))


def summarize_case_detection(
    cases: list[IdentityCase],
    *,
    synthetic_event_indices: set[int],
    injection_type: str,
) -> dict[str, Any]:
    """Summarize case-level detection for a benchmark run."""
    synthetic_cases = [
        case for case in cases
        if any(index in synthetic_event_indices for index in case.representative_event_indices)
    ]
    matching_case_types = {
        "session_hijack": "session_takeover_case",
        "password_spraying": "password_spray_case",
        "low_and_slow": "low_and_slow_campaign_case",
        "coordinated_campaign": "coordinated_identity_campaign_case",
        "mfa_bypass": "session_takeover_case",
        "identity_drift": "session_takeover_case",
        "temporal_jitter": "coordinated_identity_campaign_case",
    }
    expected_case_type = matching_case_types.get(injection_type, "coordinated_identity_campaign_case")
    detected_matching = any(case.case_type == expected_case_type for case in synthetic_cases)
    return {
        "ground_truth_case_count": 1 if synthetic_event_indices else 0,
        "detected_case_count": 1 if synthetic_cases else 0,
        "synthetic_case_count": len(synthetic_cases),
        "case_detection_rate": 1.0 if synthetic_cases else 0.0,
        "matching_expected_case_type": detected_matching,
        "expected_case_type": expected_case_type,
    }


def _build_cases(
    *,
    case_type: str,
    candidates: list[dict[str, Any]],
    key_fn,
    case_time_window_minutes: int,
    require_multi_user: bool = False,
) -> list[IdentityCase]:
    if not candidates:
        return []

    grouped: dict[tuple[Any, ...], list[list[dict[str, Any]]]] = {}
    for item in sorted(candidates, key=lambda row: row["event"].timestamp):
        base_key = key_fn(item)
        buckets = grouped.setdefault(base_key, [])
        if not buckets:
            buckets.append([item])
            continue
        last_bucket = buckets[-1]
        last_ts = last_bucket[-1]["event"].timestamp
        if item["event"].timestamp - last_ts <= timedelta(minutes=case_time_window_minutes):
            last_bucket.append(item)
        else:
            buckets.append([item])

    built: list[IdentityCase] = []
    for buckets in grouped.values():
        for bucket in buckets:
            users = sorted({row["event"].user_id for row in bucket if row["event"].user_id})
            if require_multi_user and len(users) < 2:
                continue
            case = _case_from_bucket(case_type, bucket)
            built.append(case)
    return built


def _case_from_bucket(case_type: str, bucket: list[dict[str, Any]]) -> IdentityCase:
    events = [row["event"] for row in bucket]
    indices = sorted({row["result"].event_index for row in bucket})
    score = max(
        max(row["takeover_score"], row["sequence_score"], row["campaign_score"], row["spray_score"], row["low_and_slow_score"])
        for row in bucket
    )
    severity = _severity_from_score(score, len(indices))
    confidence = _confidence_band(score)
    reasons = _collect_reasons(bucket)
    case_hash = sha1(f"{case_type}:{','.join(str(idx) for idx in indices)}".encode("utf-8")).hexdigest()[:12]
    return IdentityCase(
        case_id=f"{case_type}:{case_hash}",
        case_type=case_type,
        severity=severity,
        confidence_band=confidence,
        score=score,
        first_seen=min(event.timestamp for event in events),
        last_seen=max(event.timestamp for event in events),
        involved_users=sorted({event.user_id for event in events if event.user_id}),
        involved_sessions=sorted({event.session_id for event in events if event.session_id}),
        involved_ips=sorted({event.ip_address for event in events if event.ip_address}),
        involved_devices=sorted({
            value
            for event in events
            for value in (event.device_fingerprint, event.user_agent)
            if value
        }),
        involved_asns=sorted({event.asn for event in events if event.asn}),
        representative_event_indices=indices[:12],
        reasons=reasons[:4],
    )


def _severity_from_score(score: float, event_count: int) -> str:
    if score >= 0.85 or event_count >= 8:
        return "critical"
    if score >= 0.7 or event_count >= 5:
        return "high"
    if score >= 0.55 or event_count >= 3:
        return "medium"
    return "low"


def _confidence_band(score: float) -> str:
    if score >= 0.85:
        return "very_high"
    if score >= 0.7:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def _collect_reasons(bucket: list[dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    for row in bucket:
        for reason in row["result"].research_reasons:
            if reason not in reasons:
                reasons.append(reason)
    if not reasons:
        reasons.append("Deterministic identity case aggregation triggered from research signals.")
    return reasons

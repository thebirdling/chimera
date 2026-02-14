"""
Correlation engine for Chimera.

Identifies relationships between events across users and sessions
to detect coordinated attacks, credential stuffing campaigns, and
lateral movement patterns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from collections import defaultdict
import logging

from chimera.data_loader import AuthEvent

logger = logging.getLogger(__name__)


@dataclass
class CorrelationCluster:
    """A group of related events linked by a shared attribute."""

    cluster_id: str
    correlation_type: str  # "shared_ip", "timing_burst", "shared_session_pattern"
    description: str
    severity: str = "medium"
    events: list[int] = field(default_factory=list)  # event indices
    users: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "correlation_type": self.correlation_type,
            "description": self.description,
            "severity": self.severity,
            "event_count": len(self.events),
            "user_count": len(self.users),
            "events": self.events,
            "users": self.users,
            "attributes": self.attributes,
        }


class EventCorrelator:
    """
    Cross-references events to find coordinated or related activity.

    Correlation strategies:

    - **Shared IP**: Multiple users authenticating from the same IP within
      a short window — possible credential-stuffing or shared compromise.
    - **Timing burst**: A burst of logins across many users in a short
      window, regardless of IP — possible automated campaign.
    - **Session pattern**: Users exhibiting similar anomalous session
      patterns (e.g. same duration, same failure sequence).
    """

    def __init__(
        self,
        ip_window_minutes: int = 30,
        burst_window_minutes: int = 5,
        min_users_for_cluster: int = 3,
    ):
        self.ip_window = timedelta(minutes=ip_window_minutes)
        self.burst_window = timedelta(minutes=burst_window_minutes)
        self.min_users = min_users_for_cluster
        self._cluster_counter = 0

    def correlate(self, events: list[AuthEvent]) -> list[CorrelationCluster]:
        """
        Run all correlation strategies and return clusters.

        Args:
            events: Sorted list of AuthEvent objects.

        Returns:
            List of CorrelationCluster objects.
        """
        clusters: list[CorrelationCluster] = []
        clusters.extend(self.correlate_by_ip(events))
        clusters.extend(self.correlate_by_timing(events))
        clusters.extend(self.correlate_by_failure_pattern(events))

        logger.info(
            f"Correlation complete: {len(clusters)} clusters found "
            f"across {len(events)} events"
        )
        return clusters

    def correlate_by_ip(self, events: list[AuthEvent]) -> list[CorrelationCluster]:
        """Find multiple users sharing an IP in a short time window."""
        clusters = []
        ip_events: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)

        for idx, event in enumerate(events):
            if event.ip_address:
                ip_events[event.ip_address].append((idx, event))

        for ip, ip_list in ip_events.items():
            ip_list.sort(key=lambda x: x[1].timestamp)

            i = 0
            while i < len(ip_list):
                window_end = ip_list[i][1].timestamp + self.ip_window
                burst = [e for e in ip_list[i:] if e[1].timestamp <= window_end]
                unique_users = set(e[1].user_id for e in burst)

                if len(unique_users) >= self.min_users:
                    self._cluster_counter += 1
                    clusters.append(
                        CorrelationCluster(
                            cluster_id=f"ip_{self._cluster_counter}",
                            correlation_type="shared_ip",
                            description=(
                                f"{len(unique_users)} users from IP {ip} "
                                f"within {int(self.ip_window.total_seconds() / 60)}m"
                            ),
                            severity="high" if len(unique_users) >= 5 else "medium",
                            events=[e[0] for e in burst],
                            users=sorted(unique_users),
                            attributes={
                                "ip_address": ip,
                                "unique_users": len(unique_users),
                                "event_count": len(burst),
                            },
                        )
                    )
                    i += len(burst)
                else:
                    i += 1

        return clusters

    def correlate_by_timing(
        self, events: list[AuthEvent]
    ) -> list[CorrelationCluster]:
        """Detect bursts of logins across multiple users in a tight window."""
        clusters = []
        sorted_indexed = sorted(enumerate(events), key=lambda x: x[1].timestamp)

        i = 0
        while i < len(sorted_indexed):
            idx_i, ev_i = sorted_indexed[i]
            window_end = ev_i.timestamp + self.burst_window

            burst = [
                (idx, ev)
                for idx, ev in sorted_indexed[i:]
                if ev.timestamp <= window_end
            ]
            unique_users = set(ev.user_id for _, ev in burst)

            if len(unique_users) >= self.min_users:
                self._cluster_counter += 1
                unique_ips = set(
                    ev.ip_address for _, ev in burst if ev.ip_address
                )
                clusters.append(
                    CorrelationCluster(
                        cluster_id=f"burst_{self._cluster_counter}",
                        correlation_type="timing_burst",
                        description=(
                            f"{len(burst)} events from {len(unique_users)} users "
                            f"within {int(self.burst_window.total_seconds() / 60)}m"
                        ),
                        severity="high",
                        events=[idx for idx, _ in burst],
                        users=sorted(unique_users),
                        attributes={
                            "unique_users": len(unique_users),
                            "unique_ips": len(unique_ips),
                            "event_count": len(burst),
                        },
                    )
                )
                i += len(burst)
            else:
                i += 1

        return clusters

    def correlate_by_failure_pattern(
        self, events: list[AuthEvent]
    ) -> list[CorrelationCluster]:
        """Find users exhibiting similar failure patterns."""
        clusters = []

        # Build per-user failure sequences
        user_failures: dict[str, list[tuple[int, AuthEvent]]] = defaultdict(list)
        for idx, event in enumerate(events):
            if event.is_failure:
                user_failures[event.user_id].append((idx, event))

        # Find users with suspiciously similar failure counts and timing
        high_failure_users = {
            uid: fails
            for uid, fails in user_failures.items()
            if len(fails) >= 3
        }

        if len(high_failure_users) >= self.min_users:
            all_events = []
            all_users = []
            for uid, fails in high_failure_users.items():
                all_events.extend([idx for idx, _ in fails])
                all_users.append(uid)

            self._cluster_counter += 1
            clusters.append(
                CorrelationCluster(
                    cluster_id=f"fail_pattern_{self._cluster_counter}",
                    correlation_type="shared_failure_pattern",
                    description=(
                        f"{len(all_users)} users with 3+ authentication failures"
                    ),
                    severity="medium",
                    events=all_events,
                    users=sorted(all_users),
                    attributes={
                        "users_with_failures": len(all_users),
                        "total_failures": len(all_events),
                    },
                )
            )

        return clusters

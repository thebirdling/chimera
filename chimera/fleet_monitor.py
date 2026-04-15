"""
chimera.fleet_monitor — Cross-user coordinated attack detection (v0.4.2).

Defends against attack vectors that evade individual-user anomaly detection
by distributing their footprint across many users simultaneously.

Threat models addressed
-----------------------
1. **Credential stuffing** (low-and-slow): 1 login per user per month across
   hundreds of accounts → each user's individual score is zero.

2. **Mass new-IP event**: sudden surge in users logging in from IPs they've
   never used → new IP addresses across many users in a short window.

3. **ASN concentration**: majority of logins suddenly originating from a
   single new ASN → suggests a single infrastructure actor (VPN, datacenter,
   botnet) behind many compromised accounts.

4. **Synchronized anomaly**: an unusually high fraction of the population
   is simultaneously flagged as individually anomalous → coordinated attack.

Architecture
------------
FleetMonitor maintains ROLLING COUNTERS over a sliding time window using
a deque of per-minute buckets. This allows O(1) per-event updates and
O(W) window expiry where W is the window width in minutes.

All statistics are stored in memory only. A restart clears the window
(this is acceptable — the counters represent recent activity, not history).

Thread safety
-------------
All public methods are protected by a single threading.Lock for safe use
from the StreamingBuffer worker thread.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Defaults
# ------------------------------------------------------------------
_DEFAULT_WINDOW_MINUTES = 60         # rolling detection window
_DEFAULT_MASS_NEW_IP_THRESHOLD = 0.20    # 20% of users login from new IP in window
_DEFAULT_ASN_CONCENTRATION = 0.50       # 50% of logins from a single new ASN
_DEFAULT_SYNC_ANOMALY_THRESHOLD = 0.30  # 30% of users simultaneously flagged
_DEFAULT_MIN_POPULATION = 10            # don't fire until we've seen at least N users


@dataclass
class FleetAlert:
    """A fleet-level anomaly detection result."""
    alert_type: str          # MASS_NEW_IP | ASN_CONCENTRATION | SYNCHRONIZED_ANOMALY
    severity: str            # WARNING | CRITICAL
    affected_fraction: float # fraction of active users affected
    detail: str              # human-readable explanation
    timestamp: str


class FleetMonitor:
    """Rolling window cross-user anomaly detector.

    Parameters
    ----------
    window_minutes:
        Rolling detection window length in minutes.
    mass_new_ip_threshold:
        Fraction of users that must have a new-IP login in the window
        to trigger MASS_NEW_IP alert.
    asn_concentration_threshold:
        Fraction of logins in the window from a single ASN to trigger
        ASN_CONCENTRATION alert.
    sync_anomaly_threshold:
        Fraction of population simultaneously individually-anomalous to
        trigger SYNCHRONIZED_ANOMALY alert.
    min_population:
        Minimum distinct users seen in the window before any alerts fire.
        Prevents spurious alerts during bootstrap/low-traffic periods.
    """

    def __init__(
        self,
        window_minutes: int = _DEFAULT_WINDOW_MINUTES,
        mass_new_ip_threshold: float = _DEFAULT_MASS_NEW_IP_THRESHOLD,
        asn_concentration_threshold: float = _DEFAULT_ASN_CONCENTRATION,
        sync_anomaly_threshold: float = _DEFAULT_SYNC_ANOMALY_THRESHOLD,
        min_population: int = _DEFAULT_MIN_POPULATION,
    ) -> None:
        self.window_minutes = window_minutes
        self.mass_new_ip_threshold = mass_new_ip_threshold
        self.asn_concentration_threshold = asn_concentration_threshold
        self.sync_anomaly_threshold = sync_anomaly_threshold
        self.min_population = min_population

        self._lock = threading.Lock()

        # Rolling per-minute buckets
        self._buckets: deque = deque()   # each bucket: (ts_minute, {data})
        self._window_seconds = window_minutes * 60.0

        # Long-term per-user IP history (for new-IP detection)
        self._user_known_ips: dict[str, set] = defaultdict(set)
        self._user_known_asns: dict[str, set] = defaultdict(set)

        # Recent alert dedup
        self._last_alert_ts: dict[str, float] = {}
        self._alert_cooldown_seconds = 300.0  # 5 min cooldown per alert type

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_login(
        self,
        user: str,
        ip: Optional[str] = None,
        asn: Optional[str] = None,
        is_anomalous: bool = False,
    ) -> list[FleetAlert]:
        """Record one login event and check for fleet-level anomalies.

        Parameters
        ----------
        user:
            User identifier.
        ip:
            Source IP address (optional, used for new-IP detection).
        asn:
            Source ASN (optional, used for ASN concentration detection).
        is_anomalous:
            True if this event was individually flagged as anomalous by
            the per-user detection pipeline.

        Returns
        -------
        List of FleetAlert objects (may be empty).
        """
        with self._lock:
            now = time.monotonic()
            self._expire_old_buckets(now)

            # Add to current minute bucket
            current_bucket = self._get_or_create_bucket(now)
            current_bucket["users"].add(user)
            if ip:
                is_new_ip = ip not in self._user_known_ips[user]
                if is_new_ip:
                    current_bucket["new_ip_users"].add(user)
                    self._user_known_ips[user].add(ip)
            if asn:
                is_new_asn = asn not in self._user_known_asns[user]
                if is_new_asn:
                    self._user_known_asns[user].add(asn)
                current_bucket["logins_by_asn"][asn] = (
                    current_bucket["logins_by_asn"].get(asn, 0) + 1
                )
            if is_anomalous:
                current_bucket["anomalous_users"].add(user)

            return self._evaluate_fleet()

    def population_size(self) -> int:
        """Return number of distinct users seen in the current window."""
        with self._lock:
            all_users: set = set()
            for _, bucket in self._buckets:
                all_users |= bucket["users"]
            return len(all_users)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _expire_old_buckets(self, now: float) -> None:
        while self._buckets and (now - self._buckets[0][0]) > self._window_seconds:
            self._buckets.popleft()

    def _get_or_create_bucket(self, now: float) -> dict:
        # Use 60-second granularity
        ts_minute = int(now / 60.0) * 60
        if self._buckets and self._buckets[-1][0] == ts_minute:
            return self._buckets[-1][1]
        bucket = {
            "users": set(),
            "new_ip_users": set(),
            "anomalous_users": set(),
            "logins_by_asn": {},
        }
        self._buckets.append((ts_minute, bucket))
        return bucket

    def _aggregate_window(self) -> dict:
        """Merge all buckets in the current window."""
        agg = {
            "users": set(),
            "new_ip_users": set(),
            "anomalous_users": set(),
            "logins_by_asn": defaultdict(int),
            "total_logins": 0,
        }
        for _, bucket in self._buckets:
            agg["users"] |= bucket["users"]
            agg["new_ip_users"] |= bucket["new_ip_users"]
            agg["anomalous_users"] |= bucket["anomalous_users"]
            for asn, count in bucket["logins_by_asn"].items():
                agg["logins_by_asn"][asn] += count
            agg["total_logins"] += sum(bucket["logins_by_asn"].values())
        return agg

    def _evaluate_fleet(self) -> list[FleetAlert]:
        agg = self._aggregate_window()
        pop = len(agg["users"])

        if pop < self.min_population:
            return []

        alerts = []
        now = datetime.now(timezone.utc).isoformat()

        # ---- MASS_NEW_IP ----
        new_ip_frac = len(agg["new_ip_users"]) / pop
        if new_ip_frac >= self.mass_new_ip_threshold:
            if self._cooldown_ok("MASS_NEW_IP"):
                alerts.append(FleetAlert(
                    alert_type="MASS_NEW_IP",
                    severity="CRITICAL" if new_ip_frac >= 0.40 else "WARNING",
                    affected_fraction=new_ip_frac,
                    detail=(
                        f"{len(agg['new_ip_users'])}/{pop} users ({new_ip_frac:.1%}) "
                        f"logged in from a new IP in the last {self.window_minutes} min. "
                        f"Possible credential stuffing or mass account compromise."
                    ),
                    timestamp=now,
                ))
                logger.warning(
                    "[fleet] MASS_NEW_IP: %.1f%% of users from new IPs in %d-min window.",
                    new_ip_frac * 100, self.window_minutes,
                )

        # ---- ASN_CONCENTRATION ----
        total_logins = agg["total_logins"]
        if total_logins > 0 and agg["logins_by_asn"]:
            top_asn, top_count = max(agg["logins_by_asn"].items(), key=lambda x: x[1])
            asn_frac = top_count / total_logins
            if asn_frac >= self.asn_concentration_threshold:
                if self._cooldown_ok("ASN_CONCENTRATION"):
                    alerts.append(FleetAlert(
                        alert_type="ASN_CONCENTRATION",
                        severity="CRITICAL" if asn_frac >= 0.75 else "WARNING",
                        affected_fraction=asn_frac,
                        detail=(
                            f"{asn_frac:.1%} of logins in window originate from "
                            f"ASN {top_asn!r} ({top_count}/{total_logins} total). "
                            f"Possible single-actor infrastructure behind multiple accounts."
                        ),
                        timestamp=now,
                    ))
                    logger.warning(
                        "[fleet] ASN_CONCENTRATION: %.1f%% from ASN %r.",
                        asn_frac * 100, top_asn,
                    )

        # ---- SYNCHRONIZED_ANOMALY ----
        anomaly_frac = len(agg["anomalous_users"]) / pop
        if anomaly_frac >= self.sync_anomaly_threshold:
            if self._cooldown_ok("SYNCHRONIZED_ANOMALY"):
                alerts.append(FleetAlert(
                    alert_type="SYNCHRONIZED_ANOMALY",
                    severity="CRITICAL" if anomaly_frac >= 0.5 else "WARNING",
                    affected_fraction=anomaly_frac,
                    detail=(
                        f"{len(agg['anomalous_users'])}/{pop} users ({anomaly_frac:.1%}) "
                        f"are simultaneously individually anomalous. "
                        f"Possible coordinated or infrastructure-wide attack."
                    ),
                    timestamp=now,
                ))
                logger.warning(
                    "[fleet] SYNCHRONIZED_ANOMALY: %.1f%% of users simultaneously anomalous.",
                    anomaly_frac * 100,
                )

        return alerts

    def _cooldown_ok(self, alert_type: str) -> bool:
        """Return True if enough time has passed since the last alert of this type."""
        now = time.monotonic()
        last = self._last_alert_ts.get(alert_type, 0.0)
        if now - last >= self._alert_cooldown_seconds:
            self._last_alert_ts[alert_type] = now
            return True
        return False

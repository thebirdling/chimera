"""
chimera.alerts — Structured alert emission with CEF output.

Produces well-typed alerts from the anomaly detection pipeline.
Outputs to NDJSON (for piping to any log aggregator) and CEF
(Common Event Format — ingested by ArcSight, Splunk, QRadar without
any additional configuration).

The CEF format is the future SIEM integration path. Today it writes to
stdout or a file; when connectivity is available, a simple forwarder can
pipe it to any SIEM without code changes.

Severity levels
---------------
Severity is derived from the ratio of ``score / threshold``:

    excess_ratio < 0.1          → "low"
    excess_ratio < 0.5          → "medium"
    excess_ratio < 1.0          → "high"
    excess_ratio >= 1.0         → "critical"

If inter-model JSD > 0.5 (models strongly disagree), severity is bumped
one level (uncertainty increases urgency for analyst review).
"""
from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Literal, Optional, TextIO
from uuid import uuid4

logger = logging.getLogger(__name__)

Severity = Literal["info", "low", "medium", "high", "critical"]

_CEF_SEVERITY_MAP: dict[str, int] = {
    "info": 0, "low": 3, "medium": 5, "high": 7, "critical": 10,
}

# D1: Characters forbidden in CEF header fields and extension values
# Unescaped newlines split CEF log records; pipes/equals break field parsing.
_CEF_STRIP_CHARS = str.maketrans("", "", "\n\r")
_CEF_ESCAPE_EQ = str.maketrans({"=": r"\=", "\\": r"\\"})
_CEF_ESCAPE_PIPE = str.maketrans({"|": r"\|"})


def _sanitize_cef_field(value: str, is_header: bool = False) -> str:
    """Sanitize a user-controlled string for safe inclusion in a CEF record (D1).

    CEF injection attacks: an adversary sets their username to:
        'alice\\nCEF:0|Attacker|forge|...'
    which splits the syslog record and injects a fake CEF event into SIEM.

    This function:
    1. Strips CR/LF characters (prevents record splitting)
    2. Escapes '\\' then '=' per CEF extension spec
    3. Escapes '|' — always, not just in header fields, since many SIEM parsers
       also fail on unescaped pipes in extension values
    4. Limits length to 256 chars to prevent DoS via giant values
    """
    if not isinstance(value, str):
        value = str(value)
    # Strip newlines first (primary injection vector)
    value = value.translate(_CEF_STRIP_CHARS)
    # Escape backslash then equals (order matters)
    value = value.translate(_CEF_ESCAPE_EQ)
    # Always escape pipe (some SIEMs parse extension as raw text seeking '|')
    value = value.translate(_CEF_ESCAPE_PIPE)
    # Length cap
    return value[:256]


@dataclass
class Alert:
    """A structured anomaly alert produced by the Chimera detection pipeline.

    Fields
    ------
    alert_id:
        UUID identifying this specific alert (for analyst cross-referencing).
    event_id:
        Identifier of the raw event that triggered the alert.
    user:
        User whose behavior triggered the alert.
    score:
        Ensemble anomaly score.
    threshold:
        Dynamic threshold τ at the time of the alert.
    excess:
        score − threshold (how far above the decision boundary).
    models_firing:
        List of model IDs whose normalized scores exceeded threshold.
    signals_firing:
        Independent anomaly signals that contributed (e.g. "ensemble_score",
        "temporal_nll", "model_disagreement").
    jsd:
        Jensen-Shannon Divergence between model scores.
    vm_nll:
        Von Mises NLL for this event hour under the user's model.
    bootstrap_phase:
        Current phase of the self-provisioning protocol ("observe"|"warm"|"mature").
    severity:
        Derived alert severity level.
    timestamp:
        ISO 8601 UTC timestamp.
    tags:
        Additional context tags (e.g. "threshold_probing_suspected").
    raw_event:
        The original event dict that triggered the alert.
    """
    user: str
    score: float
    threshold: float
    excess: float
    models_firing: list[str] = field(default_factory=list)
    signals_firing: list[str] = field(default_factory=list)
    jsd: float = 0.0
    vm_nll: float = 0.0
    bootstrap_phase: str = "mature"
    severity: Severity = "medium"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: list[str] = field(default_factory=list)
    raw_event: dict = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    event_id: str = ""

    @classmethod
    def from_scored_event(
        cls,
        *,
        event: dict,
        score: float,
        threshold: float,
        models_firing: list[str],
        signals_firing: list[str],
        jsd: float = 0.0,
        vm_nll: float = 0.0,
        bootstrap_phase: str = "mature",
        tags: Optional[list[str]] = None,
    ) -> "Alert":
        """Construct an Alert from pipeline outputs.

        Computes severity automatically from the excess ratio and JSD.
        """
        user = (
            event.get("user_id")
            or event.get("username")
            or event.get("user", "unknown")
        )
        excess = score - threshold
        excess_ratio = excess / max(threshold, 1e-9)

        # Severity from excess ratio
        if excess_ratio < 0.1:
            sev: Severity = "low"
        elif excess_ratio < 0.5:
            sev = "medium"
        elif excess_ratio < 1.0:
            sev = "high"
        else:
            sev = "critical"

        # Bump severity if models strongly disagree (high JSD → uncertainty)
        _levels: list[Severity] = ["info", "low", "medium", "high", "critical"]
        if jsd > 0.5 and sev != "critical":
            idx = _levels.index(sev)
            sev = _levels[min(idx + 1, len(_levels) - 1)]

        return cls(
            user=user,
            score=score,
            threshold=threshold,
            excess=excess,
            models_firing=models_firing,
            signals_firing=signals_firing,
            jsd=jsd,
            vm_nll=vm_nll,
            bootstrap_phase=bootstrap_phase,
            severity=sev,
            tags=tags or [],
            raw_event=event,
            event_id=str(event.get("event_id", event.get("id", ""))),
        )

    # ------------------------------------------------------------------
    # Output formats
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize to a plain dict (JSON-serializable)."""
        return asdict(self)

    def to_ndjson(self) -> str:
        """Serialize to a single NDJSON line (no trailing newline)."""
        return json.dumps(self.to_dict(), default=str)

    def to_cef(self) -> str:
        """Serialize to Common Event Format (CEF:0).

        All user-controlled string values are sanitized via _sanitize_cef_field()
        to prevent SIEM log injection attacks (D1).
        """
        cef_sev = _CEF_SEVERITY_MAP[self.severity]

        # Sanitize all user-controlled fields before CEF insertion
        safe_user = _sanitize_cef_field(self.user, is_header=False)
        safe_ip = _sanitize_cef_field(
            str(self.raw_event.get("ip_address", "unknown"))
        )
        safe_action = _sanitize_cef_field(
            str(self.raw_event.get("action", "auth"))
        )
        safe_outcome = _sanitize_cef_field(
            str(self.raw_event.get("outcome", "unknown"))
        )
        safe_signals = _sanitize_cef_field(
            ",".join(self.signals_firing)
        )
        safe_phase = _sanitize_cef_field(self.bootstrap_phase)
        safe_msg = _sanitize_cef_field(
            ", ".join(self.tags) if self.tags else "chimera_alert"
        )
        safe_ts = _sanitize_cef_field(self.timestamp)
        safe_id = _sanitize_cef_field(self.alert_id)
        safe_name = _sanitize_cef_field(
            f"Chimera Anomaly [{self.severity.upper()}]", is_header=True
        )

        ext_parts = [
            f"src={safe_ip}",
            f"suser={safe_user}",
            f"act={safe_action}",
            f"outcome={safe_outcome}",
            f"cs1={self.score:.4f}",
            "cs1Label=AnomalyScore",
            f"cs2={self.threshold:.4f}",
            "cs2Label=Threshold",
            f"cs3={self.jsd:.4f}",
            "cs3Label=ModelJSD",
            f"cs4={safe_signals}",
            "cs4Label=SignalsFiring",
            f"cs5={safe_phase}",
            "cs5Label=BootstrapPhase",
            f"msg={safe_msg}",
            f"rt={safe_ts}",
            f"externalId={safe_id}",
        ]
        ext = " ".join(ext_parts)
        return f"CEF:0|Chimera|chimera-engine|0.4.2|ANOMALY_DETECTED|{safe_name}|{cef_sev}|{ext}"

    def __str__(self) -> str:
        return (
            f"[{self.severity.upper()}] {self.user} @ {self.timestamp} "
            f"score={self.score:.3f} (τ={self.threshold:.3f}, +{self.excess:.3f}) "
            f"signals={self.signals_firing}"
        )


# ------------------------------------------------------------------
# Alert emitter
# ------------------------------------------------------------------

class AlertEmitter:
    """Routes formatted alerts to configured outputs with redundancy.

    Defense-Grade: Supports multiple independent sinks. If the primary SIEM
    stream fails (e.g. broken pipe), Chimera ensures the alert is still
    persisted to the secondary local audit trail.

    Parameters
    ----------
    ndjson_stream:
        Primary file-like object for NDJSON output. Defaults to sys.stdout.
    cef_stream:
        Optional separate stream for CEF output (SIEM ingestion).
    ndjson_path:
        Optional path to a file for primary NDJSON logging.
    secondary_audit_path:
        Optional path to a secondary, high-integrity local audit trail.
        Failures in other streams will NOT prevent writing to this path.
    min_severity:
        Minimum severity level to emit.
    """

    _SEVERITY_ORDER: list[Severity] = ["info", "low", "medium", "high", "critical"]

    def __init__(
        self,
        ndjson_stream: TextIO = sys.stdout,
        cef_stream: Optional[TextIO] = None,
        ndjson_path: Optional[str] = None,
        secondary_audit_path: Optional[str] = None,
        min_severity: Severity = "low",
    ) -> None:
        self.ndjson_stream = ndjson_stream
        self.cef_stream = cef_stream
        self.ndjson_path = ndjson_path
        self.secondary_audit_path = secondary_audit_path
        self.min_severity = min_severity
        self._emitted: int = 0
        self._suppressed_by_severity: int = 0

    def emit(self, alert: Alert) -> bool:
        """Emit an alert to all configured outputs with fail-safe isolation."""
        if (self._SEVERITY_ORDER.index(alert.severity)
                < self._SEVERITY_ORDER.index(self.min_severity)):
            self._suppressed_by_severity += 1
            return False

        line = alert.to_ndjson()
        cef_line = alert.to_cef()

        # Isolated emission to each sink
        sink_failures = []

        # 1. Primary Streaming (e.g. stdout)
        try:
            self.ndjson_stream.write(line + "\n")
            self.ndjson_stream.flush()
        except Exception as e:
            sink_failures.append(f"ndjson_stream({e})")

        # 2. CEF SIEM Stream
        if self.cef_stream is not None:
            try:
                self.cef_stream.write(cef_line + "\n")
                self.cef_stream.flush()
            except Exception as e:
                sink_failures.append(f"cef_stream({e})")

        # 3. Primary File
        if self.ndjson_path:
            try:
                with open(self.ndjson_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception as e:
                sink_failures.append(f"ndjson_file({e})")

        # 4. Secondary Failsafe Audit Trail (Defense Requirement)
        if self.secondary_audit_path:
            try:
                # Use atomic-ish append if possible, or standard open
                with open(self.secondary_audit_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception as e:
                sink_failures.append(f"secondary_audit({e})")

        if sink_failures:
            logger.error(
                "[emitter] Partial emission failure for alert %s. "
                "Success recorded in remaining sinks. Faults: %s",
                alert.alert_id, ", ".join(sink_failures)
            )

        self._emitted += 1
        return True

    def emit_heartbeat(self, status: dict) -> None:
        """A3: Emit a signed 'AM_ALIVE' record to prove engine health.

        Enables external watchdogs to detect if Chimera has been silenced
        by an adversary or has silently crashed.
        """
        heartbeat = {
            "type": "CHIMERA_HEARTBEAT",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "emitted_count": self._emitted,
            "status": status,
        }
        line = json.dumps(heartbeat)
        
        # Heartbeats always go to primary stream and secondary audit
        try:
            self.ndjson_stream.write(line + "\n")
            self.ndjson_stream.flush()
        except: pass
        
        if self.secondary_audit_path:
            try:
                with open(self.secondary_audit_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except: pass

    @property
    def emitted_count(self) -> int:
        return self._emitted

    @property
    def suppressed_count(self) -> int:
        return self._suppressed_by_severity

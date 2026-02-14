"""
SIEM-compatible exporters for Chimera.

Provides output in standard security formats:
- CEF (ArcSight Common Event Format)
- Syslog (RFC 5424)
- STIX 2.1 JSON bundles
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union
import json
import uuid
import logging

from chimera.scoring import AnomalyResult
from chimera.rules.engine import RuleMatch

logger = logging.getLogger(__name__)


class CEFExporter:
    """
    Export anomaly results as ArcSight Common Event Format lines.

    CEF format:
        CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    """

    VENDOR = "Chimera"
    PRODUCT = "BehavioralAnomalyDetector"
    VERSION = "0.2.0"

    SEVERITY_MAP = {"low": 3, "medium": 5, "high": 7, "critical": 10}

    def export_results(
        self,
        results: list[AnomalyResult],
        output_path: Union[str, Path],
    ) -> Path:
        """Export anomaly results as CEF log lines."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        for result in results:
            if not result.is_anomaly:
                continue
            lines.append(self._result_to_cef(result))

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            if lines:
                f.write("\n")

        logger.info(f"CEF export: {len(lines)} events written to {path}")
        return path

    def export_rule_matches(
        self,
        matches: list[RuleMatch],
        output_path: Union[str, Path],
    ) -> Path:
        """Export rule matches as CEF log lines."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = [self._rule_to_cef(m) for m in matches]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            if lines:
                f.write("\n")

        logger.info(f"CEF export: {len(lines)} rule matches written to {path}")
        return path

    def _result_to_cef(self, result: AnomalyResult) -> str:
        severity = self._score_to_severity(result.anomaly_score)
        ts = result.timestamp.strftime("%b %d %Y %H:%M:%S") if result.timestamp else ""

        ext_parts = [
            f"rt={ts}",
            f"suser={result.user_id}",
            f"cs1={result.event_type}",
            f"cs1Label=EventType",
            f"cfp1={result.anomaly_score:.6f}",
            f"cfp1Label=AnomalyScore",
            f"cfp2={result.confidence:.4f}",
            f"cfp2Label=Confidence",
        ]
        extension = " ".join(ext_parts)

        return (
            f"CEF:0|{self.VENDOR}|{self.PRODUCT}|{self.VERSION}"
            f"|anomaly|Behavioral Anomaly|{severity}|{extension}"
        )

    def _rule_to_cef(self, match: RuleMatch) -> str:
        severity = self.SEVERITY_MAP.get(match.severity, 5)
        ts = match.timestamp.strftime("%b %d %Y %H:%M:%S") if match.timestamp else ""
        users_str = ",".join(match.matched_users[:5])

        ext_parts = [
            f"rt={ts}",
            f"suser={users_str}",
            f"cs1={match.rule_id}",
            f"cs1Label=RuleID",
            f"msg={match.description[:200]}",
        ]
        extension = " ".join(ext_parts)

        return (
            f"CEF:0|{self.VENDOR}|{self.PRODUCT}|{self.VERSION}"
            f"|{match.rule_id}|{match.rule_name}|{severity}|{extension}"
        )

    @staticmethod
    def _score_to_severity(score: float) -> int:
        if score < -0.4:
            return 10
        elif score < -0.2:
            return 7
        elif score < -0.1:
            return 5
        else:
            return 3


class SyslogExporter:
    """
    Export anomaly results as RFC 5424 syslog messages.
    """

    FACILITY = 10  # security/authorization
    APP_NAME = "chimera"

    def export_results(
        self,
        results: list[AnomalyResult],
        output_path: Union[str, Path],
    ) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        for result in results:
            if not result.is_anomaly:
                continue
            lines.append(self._result_to_syslog(result))

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            if lines:
                f.write("\n")

        logger.info(f"Syslog export: {len(lines)} events written to {path}")
        return path

    def _result_to_syslog(self, result: AnomalyResult) -> str:
        severity = self._score_to_syslog_severity(result.anomaly_score)
        priority = self.FACILITY * 8 + severity

        ts = (
            result.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
            if result.timestamp
            else "-"
        )

        msg = (
            f"user={result.user_id} "
            f"event={result.event_type} "
            f"score={result.anomaly_score:.4f} "
            f"confidence={result.confidence:.2f} "
            f"anomaly={result.is_anomaly}"
        )

        return f"<{priority}>1 {ts} - {self.APP_NAME} - - - {msg}"

    @staticmethod
    def _score_to_syslog_severity(score: float) -> int:
        if score < -0.4:
            return 2  # Critical
        elif score < -0.2:
            return 3  # Error
        elif score < -0.1:
            return 4  # Warning
        else:
            return 6  # Informational


class STIXExporter:
    """
    Export anomaly results as STIX 2.1 JSON bundles.

    Creates STIX Indicator and Observed-Data objects for
    threat intelligence sharing.
    """

    def export_results(
        self,
        results: list[AnomalyResult],
        output_path: Union[str, Path],
        rule_matches: list[RuleMatch] | None = None,
    ) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        objects = []

        # Identity object for Chimera
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'chimera.security')}",
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "name": "Chimera Behavioral Analysis",
            "identity_class": "system",
        }
        objects.append(identity)

        # Anomalous events as observed-data
        for result in results:
            if not result.is_anomaly:
                continue
            objects.append(self._result_to_observed_data(result, identity["id"]))

        # Rule matches as indicators
        if rule_matches:
            for match in rule_matches:
                objects.append(self._rule_to_indicator(match, identity["id"]))

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)

        logger.info(f"STIX export: {len(objects)} objects written to {path}")
        return path

    def _result_to_observed_data(
        self, result: AnomalyResult, identity_id: str
    ) -> dict[str, Any]:
        ts = (
            result.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
            if result.timestamp
            else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        return {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": f"observed-data--{uuid.uuid4()}",
            "created": ts,
            "modified": ts,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "created_by_ref": identity_id,
            "object_refs": [],
            "extensions": {
                "chimera-anomaly": {
                    "user_id": result.user_id,
                    "event_type": result.event_type,
                    "anomaly_score": result.anomaly_score,
                    "confidence": result.confidence,
                    "is_anomaly": result.is_anomaly,
                }
            },
        }

    def _rule_to_indicator(
        self, match: RuleMatch, identity_id: str
    ) -> dict[str, Any]:
        ts = (
            match.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
            if match.timestamp
            else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": ts,
            "modified": ts,
            "name": match.rule_name,
            "description": match.description,
            "indicator_types": ["anomalous-activity"],
            "pattern_type": "chimera-rule",
            "pattern": f"[chimera:rule_id = '{match.rule_id}']",
            "valid_from": ts,
            "created_by_ref": identity_id,
            "extensions": {
                "chimera-rule-match": {
                    "rule_id": match.rule_id,
                    "severity": match.severity,
                    "matched_users": match.matched_users,
                    "details": match.details,
                }
            },
        }

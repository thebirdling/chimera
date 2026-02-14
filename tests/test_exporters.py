"""
Tests for SIEM exporters (CEF, Syslog, STIX).
"""

import pytest
import json
from datetime import datetime
from pathlib import Path

from chimera.scoring import AnomalyResult
from chimera.rules.engine import RuleMatch
from chimera.exporters import CEFExporter, SyslogExporter, STIXExporter


@pytest.fixture
def sample_results():
    return [
        AnomalyResult(
            event_index=0,
            user_id="user_001",
            timestamp=datetime(2025, 1, 15, 10, 30, 0),
            event_type="login_success",
            anomaly_score=-0.3,
            is_anomaly=True,
            confidence=0.85,
        ),
        AnomalyResult(
            event_index=1,
            user_id="user_002",
            timestamp=datetime(2025, 1, 15, 11, 0, 0),
            event_type="login_failed",
            anomaly_score=0.1,
            is_anomaly=False,
            confidence=0.6,
        ),
    ]


@pytest.fixture
def sample_rule_matches():
    return [
        RuleMatch(
            rule_id="brute_force",
            rule_name="Brute Force Attack",
            severity="high",
            description="5 failed logins in 10 minutes",
            matched_events=[0, 1, 2],
            matched_users=["user_001"],
            timestamp=datetime(2025, 1, 15, 10, 0, 0),
        ),
    ]


class TestCEFExporter:
    def test_export_results(self, sample_results, tmp_path):
        exporter = CEFExporter()
        path = exporter.export_results(sample_results, tmp_path / "test.cef")

        assert path.exists()
        content = path.read_text()
        # Only anomalous events should be exported
        lines = [l for l in content.strip().split("\n") if l]
        assert len(lines) == 1
        assert "CEF:0|Chimera" in lines[0]
        assert "user_001" in lines[0]

    def test_export_rule_matches(self, sample_rule_matches, tmp_path):
        exporter = CEFExporter()
        path = exporter.export_rule_matches(sample_rule_matches, tmp_path / "rules.cef")

        assert path.exists()
        content = path.read_text()
        assert "brute_force" in content


class TestSyslogExporter:
    def test_export_results(self, sample_results, tmp_path):
        exporter = SyslogExporter()
        path = exporter.export_results(sample_results, tmp_path / "test.syslog")

        assert path.exists()
        content = path.read_text()
        lines = [l for l in content.strip().split("\n") if l]
        assert len(lines) == 1
        assert "chimera" in lines[0]
        assert "user_001" in lines[0]


class TestSTIXExporter:
    def test_export_results(self, sample_results, tmp_path):
        exporter = STIXExporter()
        path = exporter.export_results(sample_results, tmp_path / "test.stix.json")

        assert path.exists()
        data = json.loads(path.read_text())
        assert data["type"] == "bundle"
        # Identity + anomalous observed-data
        assert len(data["objects"]) >= 2

    def test_export_with_rules(self, sample_results, sample_rule_matches, tmp_path):
        exporter = STIXExporter()
        path = exporter.export_results(
            sample_results, tmp_path / "full.stix.json",
            rule_matches=sample_rule_matches,
        )

        data = json.loads(path.read_text())
        # Should include indicator objects for rule matches
        indicators = [o for o in data["objects"] if o["type"] == "indicator"]
        assert len(indicators) >= 1

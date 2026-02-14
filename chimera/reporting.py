"""
Report generation module for Chimera.

Generates reports in CSV, JSON, and Markdown formats with support
for rule match summaries, correlation clusters, and risk grades.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union
import csv
import json
import logging

from chimera.scoring import AnomalyResult, UserSummary

logger = logging.getLogger(__name__)


# ── Risk letter grades ───────────────────────────────────────────

def _risk_letter_grade(anomaly_rate: float, min_score: float) -> str:
    """Convert risk metrics to a letter grade (A–F)."""
    if anomaly_rate > 0.5 or min_score < -0.5:
        return "F"
    elif anomaly_rate > 0.3 or min_score < -0.3:
        return "D"
    elif anomaly_rate > 0.15 or min_score < -0.15:
        return "C"
    elif anomaly_rate > 0.05 or min_score < -0.05:
        return "B"
    else:
        return "A"


class ReportGenerator:
    """
    Generates anomaly detection reports in multiple formats.

    Supports CSV, JSON, and Markdown output with optional
    rule match summaries and correlation cluster details.
    """

    def __init__(self, output_dir: Union[str, Path] = "./chimera_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── CSV reports ──────────────────────────────────────────────

    def to_csv_events(
        self,
        results: list[AnomalyResult],
        prefix: str = "chimera",
    ) -> Path:
        """Export event-level results as CSV."""
        path = self.output_dir / f"{prefix}_events.csv"

        fieldnames = [
            "event_index", "user_id", "timestamp", "event_type",
            "anomaly_score", "is_anomaly", "confidence",
            "user_baseline_score", "global_percentile",
            "top_contributing_features",
        ]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                row = r.to_dict()
                # Flatten features for CSV
                row["top_contributing_features"] = "; ".join(
                    f"{feat['feature']}={feat.get('z_score', 0):.2f}"
                    for feat in row.get("top_contributing_features", [])[:3]
                )
                writer.writerow(row)

        logger.info(f"CSV events report: {path}")
        return path

    def to_csv_users(
        self,
        summaries: list[UserSummary],
        prefix: str = "chimera",
    ) -> Path:
        """Export per-user summaries as CSV."""
        path = self.output_dir / f"{prefix}_users.csv"

        fieldnames = [
            "user_id", "total_events", "anomaly_count", "anomaly_rate",
            "mean_score", "min_score", "max_score", "score_std",
            "risk_level", "risk_grade",
        ]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for s in summaries:
                row = s.to_dict()
                row["risk_grade"] = _risk_letter_grade(s.anomaly_rate, s.min_score)
                # Remove non-CSV-friendly fields
                row.pop("first_event", None)
                row.pop("last_event", None)
                row.pop("anomalous_event_indices", None)
                writer.writerow(row)

        logger.info(f"CSV users report: {path}")
        return path

    # ── JSON report ──────────────────────────────────────────────

    def to_json(
        self,
        results: list[AnomalyResult],
        user_summaries: list[UserSummary],
        score_distribution: dict[str, Any],
        rule_matches: list[dict] | None = None,
        prefix: str = "chimera",
    ) -> Path:
        """Export full report as JSON."""
        path = self.output_dir / f"{prefix}_report.json"

        report_data = {
            "generated_at": datetime.utcnow().isoformat(),
            "version": "0.2.0",
            "summary": {
                "total_events": len(results),
                "total_anomalies": sum(1 for r in results if r.is_anomaly),
                "anomaly_rate": (
                    sum(1 for r in results if r.is_anomaly) / max(len(results), 1)
                ),
                "total_users": len(user_summaries),
                "score_distribution": score_distribution,
                "rule_matches": len(rule_matches) if rule_matches else 0,
            },
            "user_summaries": [
                {**s.to_dict(), "risk_grade": _risk_letter_grade(s.anomaly_rate, s.min_score)}
                for s in user_summaries
            ],
            "anomalous_events": [r.to_dict() for r in results if r.is_anomaly],
            "all_events": [r.to_dict() for r in results],
        }

        if rule_matches:
            report_data["rule_matches"] = rule_matches

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"JSON report: {path}")
        return path

    # ── Markdown report ──────────────────────────────────────────

    def to_markdown(
        self,
        results: list[AnomalyResult],
        user_summaries: list[UserSummary],
        score_distribution: dict[str, Any],
        rule_matches: list[dict] | None = None,
        prefix: str = "chimera",
    ) -> Path:
        """Generate a comprehensive Markdown report."""
        path = self.output_dir / f"{prefix}_report.md"

        total = len(results)
        anomalies = [r for r in results if r.is_anomaly]
        n_anomalies = len(anomalies)

        lines = [
            "# 🔥 Chimera Anomaly Detection Report",
            "",
            f"*Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*",
            f"*Version: 0.2.0*",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Events | {total:,} |",
            f"| Anomalies Detected | {n_anomalies:,} |",
            f"| Anomaly Rate | {n_anomalies / max(total, 1):.1%} |",
            f"| Users Analyzed | {len(user_summaries):,} |",
        ]

        if rule_matches:
            lines.append(f"| Rule Matches | {len(rule_matches):,} |")

        # Overall risk grade
        overall_anomaly_rate = n_anomalies / max(total, 1)
        overall_min_score = min((r.anomaly_score for r in results), default=0)
        overall_grade = _risk_letter_grade(overall_anomaly_rate, overall_min_score)
        lines.extend([
            "",
            f"### Overall Risk Grade: **{overall_grade}**",
            "",
        ])

        # User risk table
        if user_summaries:
            lines.extend([
                "---",
                "",
                "## 👤 User Risk Assessment",
                "",
                "| User | Events | Anomalies | Rate | Risk | Grade |",
                "|------|--------|-----------|------|------|-------|",
            ])

            sorted_summaries = sorted(
                user_summaries,
                key=lambda s: s.anomaly_count,
                reverse=True,
            )

            for s in sorted_summaries[:20]:
                grade = _risk_letter_grade(s.anomaly_rate, s.min_score)
                risk_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                }.get(s.risk_level, "⚪")
                lines.append(
                    f"| {s.user_id} | {s.total_events} | {s.anomaly_count} "
                    f"| {s.anomaly_rate:.1%} | {risk_emoji} {s.risk_level} | {grade} |"
                )

            lines.append("")

        # Rule matches section
        if rule_matches:
            lines.extend([
                "---",
                "",
                "## 📋 Rule Match Summary",
                "",
                "| Rule | Severity | Events | Users | Description |",
                "|------|----------|--------|-------|-------------|",
            ])

            for m in rule_matches[:20]:
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                }.get(m.get("severity", ""), "⚪")
                users = m.get("matched_users", [])
                lines.append(
                    f"| {m.get('rule_name', '')} | {severity_emoji} {m.get('severity', '')} "
                    f"| {len(m.get('matched_events', []))} | {', '.join(users[:3])} "
                    f"| {m.get('description', '')[:60]} |"
                )

            lines.append("")

        # Top anomalous events
        if anomalies:
            lines.extend([
                "---",
                "",
                "## 🔍 Top Anomalous Events",
                "",
            ])

            sorted_anomalies = sorted(
                anomalies, key=lambda r: r.anomaly_score
            )[:15]

            for r in sorted_anomalies:
                lines.extend([
                    f"### Event #{r.event_index} — {r.user_id}",
                    "",
                    f"- **Timestamp:** {r.timestamp}",
                    f"- **Event Type:** {r.event_type}",
                    f"- **Anomaly Score:** {r.anomaly_score:.4f}",
                    f"- **Confidence:** {r.confidence:.1%}",
                    f"- **Percentile:** {r.global_percentile:.1%}",
                    "",
                ])

                if r.top_contributing_features:
                    lines.append("**Contributing Factors:**")
                    lines.append("")
                    for feat in r.top_contributing_features[:3]:
                        lines.append(
                            f"- `{feat.get('feature', '')}`: "
                            f"z-score={feat.get('z_score', 0):.2f}"
                        )
                    lines.append("")

        # Anomaly timeline (ASCII)
        if anomalies:
            lines.extend(self._generate_timeline(anomalies))

        # Footer
        lines.extend([
            "---",
            "",
            "*Report generated by [Chimera](https://github.com/thebirdling/chimera) v0.2.0*",
        ])

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"Markdown report: {path}")
        return path

    def _generate_timeline(self, anomalies: list[AnomalyResult]) -> list[str]:
        """Generate an ASCII timeline of anomalous events."""
        lines = [
            "---",
            "",
            "## 📅 Anomaly Timeline",
            "",
            "```",
        ]

        sorted_anomalies = sorted(anomalies, key=lambda r: r.timestamp)

        for r in sorted_anomalies[:30]:
            ts = r.timestamp.strftime("%Y-%m-%d %H:%M") if r.timestamp else "?"
            severity_bar = "█" * min(int(abs(r.anomaly_score) * 20), 20)
            lines.append(
                f"  {ts} │ {r.user_id:>12s} │ {severity_bar:<20s} │ {r.event_type}"
            )

        lines.extend(["```", ""])
        return lines

    # ── Convenience: generate all ────────────────────────────────

    def generate_all_reports(
        self,
        results: list[AnomalyResult],
        user_summaries: list[UserSummary],
        score_distribution: dict[str, Any],
        rule_matches: list[dict] | None = None,
        prefix: str = "chimera",
    ) -> dict[str, Path]:
        """Generate reports in all formats."""
        generated = {}
        generated["csv_events"] = self.to_csv_events(results, prefix)
        generated["csv_users"] = self.to_csv_users(user_summaries, prefix)
        generated["json"] = self.to_json(
            results, user_summaries, score_distribution, rule_matches, prefix
        )
        generated["markdown"] = self.to_markdown(
            results, user_summaries, score_distribution, rule_matches, prefix,
        )
        return generated

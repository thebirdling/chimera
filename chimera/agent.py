"""
Offline analyst-agent helpers for Chimera.

This module provides a deterministic local analyst surface that can triage
Chimera artifacts without requiring network access or an external LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import json

from chimera.contracts import StableEnvelope, unwrap_envelope
from chimera.engine.safe_io import safe_open_input


MAX_AGENT_ARTIFACT_BYTES = 10 * 1024 * 1024


@dataclass
class AgentRecommendation:
    title: str
    priority: str
    rationale: str

    def to_dict(self) -> dict[str, str]:
        return {
            "title": self.title,
            "priority": self.priority,
            "rationale": self.rationale,
        }


@dataclass
class AgentReview:
    source_command: str
    source_path: str
    posture: str
    summary: str
    case_overview: dict[str, Any]
    top_cases: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[AgentRecommendation] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    follow_up_questions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_command": self.source_command,
            "source_path": self.source_path,
            "posture": self.posture,
            "summary": self.summary,
            "case_overview": self.case_overview,
            "top_cases": self.top_cases,
            "recommendations": [item.to_dict() for item in self.recommendations],
            "hypotheses": self.hypotheses,
            "follow_up_questions": self.follow_up_questions,
        }


def review_artifact(input_path: str | Path) -> StableEnvelope:
    """Create a deterministic analyst review from a Chimera JSON artifact."""
    source = _resolve_artifact_path(Path(input_path))
    if source.stat().st_size > MAX_AGENT_ARTIFACT_BYTES:
        raise ValueError(
            f"Artifact exceeds safe agent review size limit of {MAX_AGENT_ARTIFACT_BYTES} bytes: {source}"
        )
    with source.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    source_command = str(data.get("command", "artifact"))
    payload = unwrap_envelope(data)
    review = _build_review(payload=payload, source_command=source_command, source_path=source)
    return StableEnvelope(command="agent-review", payload={"review": review.to_dict()})


def review_to_markdown(review: dict[str, Any]) -> str:
    """Render a compact analyst-facing markdown summary."""
    lines = [
        "# Chimera Local Analyst Review",
        "",
        f"- Source command: `{review.get('source_command', 'unknown')}`",
        f"- Source path: `{review.get('source_path', '')}`",
        f"- Posture: `{review.get('posture', 'observe')}`",
        "",
        review.get("summary", ""),
        "",
        "## Case Overview",
        "",
    ]

    overview = review.get("case_overview", {})
    for key, value in overview.items():
        lines.append(f"- {key.replace('_', ' ').title()}: `{value}`")

    recommendations = review.get("recommendations", [])
    if recommendations:
        lines.extend(["", "## Recommended Actions", ""])
        for item in recommendations:
            lines.append(
                f"- [{item.get('priority', 'medium').upper()}] {item.get('title', '')}: {item.get('rationale', '')}"
            )

    top_cases = review.get("top_cases", [])
    if top_cases:
        lines.extend(["", "## Priority Cases", ""])
        for case in top_cases:
            reasons = "; ".join(case.get("reasons", [])[:2])
            lines.append(
                f"- `{case.get('case_id', '')}` `{case.get('case_type', '')}` "
                f"severity=`{case.get('severity', '')}` score=`{case.get('score', 0)}`"
            )
            if reasons:
                lines.append(f"  Reasons: {reasons}")

    hypotheses = review.get("hypotheses", [])
    if hypotheses:
        lines.extend(["", "## Working Hypotheses", ""])
        for item in hypotheses:
            lines.append(f"- {item}")

    questions = review.get("follow_up_questions", [])
    if questions:
        lines.extend(["", "## Follow-Up Questions", ""])
        for item in questions:
            lines.append(f"- {item}")

    return "\n".join(lines).strip() + "\n"


def _resolve_artifact_path(input_path: Path) -> Path:
    input_path = input_path.resolve()
    if input_path.is_file():
        return safe_open_input(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Artifact path not found: {input_path}")

    manifest_path = input_path / "artifact_manifest.json"
    if manifest_path.exists():
        with manifest_path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        generated = manifest.get("generated_files", [])
        for candidate in generated:
            rel = candidate.get("relative_path")
            if rel and rel.endswith(".json") and "artifact_manifest" not in rel:
                resolved = (input_path / rel).resolve()
                try:
                    resolved.relative_to(input_path)
                except ValueError:
                    continue
                if resolved.exists():
                    return safe_open_input(resolved, base_dir=input_path)

    for candidate_name in ("chimera_run_report.json", "bench_report.json", "agent_review.json"):
        candidate = input_path / candidate_name
        if candidate.exists():
            return safe_open_input(candidate, base_dir=input_path)
    raise FileNotFoundError(
        f"Could not resolve a Chimera JSON artifact from directory: {input_path}"
    )


def _build_review(
    *,
    payload: dict[str, Any],
    source_command: str,
    source_path: Path,
) -> AgentReview:
    cases = payload.get("cases", []) or []
    anomalous_events = payload.get("anomalous_events", []) or []
    case_types = [case.get("case_type", "unknown") for case in cases]
    critical_cases = [case for case in cases if case.get("severity") == "critical"]
    high_cases = [case for case in cases if case.get("severity") == "high"]

    posture = "observe"
    if any(case_type == "session_takeover_case" for case_type in case_types):
        posture = "contain_now"
    elif any(
        case_type in {"password_spray_case", "coordinated_identity_campaign_case"}
        for case_type in case_types
    ):
        posture = "investigate_campaign"
    elif cases or anomalous_events:
        posture = "triage"

    top_cases = sorted(
        cases,
        key=lambda case: (
            _severity_rank(str(case.get("severity", "low"))),
            float(case.get("score", 0.0)),
            len(case.get("involved_users", []) or []),
        ),
        reverse=True,
    )[:5]

    overview = {
        "total_cases": len(cases),
        "critical_cases": len(critical_cases),
        "high_cases": len(high_cases),
        "anomalous_events": len(anomalous_events),
        "distinct_case_types": len(set(case_types)),
        "case_types": sorted(set(case_types)),
    }

    summary = _compose_summary(posture=posture, overview=overview, top_cases=top_cases)
    recommendations = _build_recommendations(posture=posture, top_cases=top_cases)
    hypotheses = _build_hypotheses(top_cases=top_cases)
    follow_up_questions = _build_questions(top_cases=top_cases, source_command=source_command)

    return AgentReview(
        source_command=source_command,
        source_path=str(source_path),
        posture=posture,
        summary=summary,
        case_overview=overview,
        top_cases=top_cases,
        recommendations=recommendations,
        hypotheses=hypotheses,
        follow_up_questions=follow_up_questions,
    )


def _compose_summary(
    *,
    posture: str,
    overview: dict[str, Any],
    top_cases: list[dict[str, Any]],
) -> str:
    if not top_cases:
        return (
            "The local analyst agent did not find grouped identity cases in this artifact. "
            "Treat the run as a baseline observation unless other telemetry raises concern."
        )
    lead = top_cases[0]
    return (
        f"Local review posture is '{posture}'. Chimera grouped {overview['total_cases']} case(s) "
        f"across {overview['distinct_case_types']} case family(ies). The highest-priority case is "
        f"{lead.get('case_type', 'unknown')} with severity {lead.get('severity', 'unknown')} and "
        f"score {lead.get('score', 0.0)}."
    )


def _build_recommendations(
    *,
    posture: str,
    top_cases: list[dict[str, Any]],
) -> list[AgentRecommendation]:
    recommendations: list[AgentRecommendation] = []
    case_types = {case.get("case_type", "unknown") for case in top_cases}

    if posture == "contain_now":
        recommendations.append(
            AgentRecommendation(
                title="Invalidate exposed sessions",
                priority="critical",
                rationale=(
                    "A takeover-style case was detected. Expire the impacted sessions and force "
                    "fresh authentication before adversary continuity hardens."
                ),
            )
        )
        recommendations.append(
            AgentRecommendation(
                title="Step-up the impacted identities",
                priority="high",
                rationale=(
                    "Require MFA or equivalent re-verification for users tied to takeover evidence "
                    "before granting continued access."
                ),
            )
        )

    if "password_spray_case" in case_types:
        recommendations.append(
            AgentRecommendation(
                title="Rate-limit and challenge shared source infrastructure",
                priority="high",
                rationale=(
                    "Password spray evidence points to cross-account auth pressure from shared "
                    "network origins; throttle or challenge those origins before retries fan out."
                ),
            )
        )

    if "coordinated_identity_campaign_case" in case_types:
        recommendations.append(
            AgentRecommendation(
                title="Cluster impacted identities by IP, device, and ASN",
                priority="high",
                rationale=(
                    "The case mix suggests coordination rather than isolated account noise. Build "
                    "an investigation set around shared infrastructure and timing overlap."
                ),
            )
        )

    if "low_and_slow_campaign_case" in case_types:
        recommendations.append(
            AgentRecommendation(
                title="Extend the investigation lookback",
                priority="medium",
                rationale=(
                    "Low-and-slow behavior often underperforms in short windows. Re-run the "
                    "analysis on a longer horizon to test persistence and drift."
                ),
            )
        )

    if not recommendations:
        recommendations.append(
            AgentRecommendation(
                title="Review the strongest anomalous identities",
                priority="medium",
                rationale=(
                    "No urgent case family fired, but the artifact still contains anomalies worth "
                    "triaging before they normalize into the baseline."
                ),
            )
        )
    return recommendations


def _build_hypotheses(*, top_cases: list[dict[str, Any]]) -> list[str]:
    case_types = {case.get("case_type", "unknown") for case in top_cases}
    hypotheses: list[str] = []
    if "session_takeover_case" in case_types:
        hypotheses.append(
            "An existing session or token was reused under a shifted client context."
        )
    if "password_spray_case" in case_types:
        hypotheses.append(
            "A shared source is testing weak credentials across multiple accounts."
        )
    if "coordinated_identity_campaign_case" in case_types:
        hypotheses.append(
            "Multiple identities are being worked through shared infrastructure as part of one campaign."
        )
    if "low_and_slow_campaign_case" in case_types:
        hypotheses.append(
            "The adversary is spreading attempts to stay below simple rate and burst thresholds."
        )
    if not hypotheses:
        hypotheses.append(
            "The artifact reflects isolated anomalies rather than a coherent identity campaign."
        )
    return hypotheses


def _build_questions(*, top_cases: list[dict[str, Any]], source_command: str) -> list[str]:
    questions: list[str] = []
    if top_cases:
        lead = top_cases[0]
        if lead.get("involved_ips"):
            questions.append(
                "Do the shared IPs in the lead case also appear in prior clean sessions for the same users?"
            )
        if lead.get("involved_devices"):
            questions.append(
                "Are the reused devices or user-agents expected fleet artifacts, or do they collapse multiple identities unexpectedly?"
            )
    if source_command.startswith("bench"):
        questions.append(
            "Does the case-level output remain stable when the contamination and injection magnitude are shifted?"
        )
    return questions[:4]


def _severity_rank(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(severity, 0)

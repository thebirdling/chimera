import json
import pytest

from chimera.agent import review_artifact, review_to_markdown
from chimera.api import review_artifact as review_artifact_api
from chimera.contracts import StableEnvelope


def test_agent_review_identifies_takeover_posture(tmp_path):
    report_path = tmp_path / "bench_report.json"
    envelope = StableEnvelope(
        command="bench",
        payload={
            "cases": [
                {
                    "case_id": "session_takeover_case:abc",
                    "case_type": "session_takeover_case",
                    "severity": "critical",
                    "score": 0.98,
                    "involved_users": ["alice"],
                    "involved_ips": ["203.0.113.10"],
                    "reasons": ["Session fingerprint drift suggests token reuse."],
                }
            ],
            "anomalous_events": [{"event_index": 1}],
        },
    )
    report_path.write_text(json.dumps(envelope.to_dict(), indent=2), encoding="utf-8")

    review = review_artifact(report_path)
    payload = review.payload["review"]

    assert payload["posture"] == "contain_now"
    assert payload["case_overview"]["critical_cases"] == 1
    assert payload["recommendations"][0]["priority"] == "critical"


def test_agent_review_resolves_artifact_directory_and_writes_outputs(tmp_path):
    out_dir = tmp_path / "chimera_output"
    out_dir.mkdir()
    report_path = out_dir / "chimera_run_report.json"
    report_path.write_text(
        json.dumps(
            StableEnvelope(command="run", payload={"cases": [], "anomalous_events": []}).to_dict(),
            indent=2,
        ),
        encoding="utf-8",
    )

    envelope = review_artifact_api(input_path=str(out_dir), output_dir=str(tmp_path / "agent"))
    artifacts = envelope.payload["artifacts"]

    assert (tmp_path / "agent" / "agent_review.json").exists()
    assert (tmp_path / "agent" / "agent_review.md").exists()
    assert artifacts["artifact_manifest"].endswith("artifact_manifest.json")


def test_review_to_markdown_contains_recommendations():
    markdown = review_to_markdown(
        {
            "source_command": "run",
            "source_path": "sample.json",
            "posture": "triage",
            "summary": "A compact summary.",
            "case_overview": {"total_cases": 1},
            "top_cases": [{"case_id": "case-1", "case_type": "password_spray_case", "severity": "high", "score": 0.8}],
            "recommendations": [{"title": "Review source IPs", "priority": "high", "rationale": "Shared source pressure detected."}],
            "hypotheses": ["This may be a spray campaign."],
            "follow_up_questions": ["Do these IPs appear in clean traffic?"],
        }
    )

    assert "Recommended Actions" in markdown
    assert "Review source IPs" in markdown
    assert "Working Hypotheses" in markdown


def test_agent_review_ignores_manifest_path_traversal(tmp_path):
    out_dir = tmp_path / "chimera_output"
    out_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps(StableEnvelope(command="run", payload={"cases": [], "anomalous_events": []}).to_dict()),
        encoding="utf-8",
    )
    (out_dir / "artifact_manifest.json").write_text(
        json.dumps(
            {
                "generated_files": [
                    {"relative_path": "..\\outside.json"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (out_dir / "chimera_run_report.json").write_text(
        json.dumps(StableEnvelope(command="run", payload={"cases": [], "anomalous_events": []}).to_dict()),
        encoding="utf-8",
    )

    review = review_artifact(out_dir)
    assert review.payload["review"]["source_path"].endswith("chimera_run_report.json")


def test_agent_review_rejects_oversized_artifact(tmp_path):
    artifact = tmp_path / "bench_report.json"
    artifact.write_bytes(b" " * (10 * 1024 * 1024 + 1))

    with pytest.raises(ValueError, match="safe agent review size limit"):
        review_artifact(artifact)

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from chimera.config import ChimeraConfig
from chimera.reporting import ReportGenerator


PRESET_SLICES = {
    "publishable_identity": [
        "baseline",
        "chimera",
        "identity_research",
        "takeover_only",
        "coordination_heavy",
        "campaign_focus",
        "infra_reuse_heavy",
        "mfa_bypass_focus",
        "spray_focus",
        "low_and_slow_focus",
        "session_concurrency_focus",
        "geo_velocity_focus",
        "examples",
    ],
    "campaign_focus": [
        "baseline",
        "chimera",
        "coordination_heavy",
        "campaign_focus",
        "infra_reuse_heavy",
        "spray_focus",
        "low_and_slow_focus",
        "session_concurrency_focus",
        "examples",
    ],
    "takeover_focus": [
        "baseline",
        "chimera",
        "takeover_only",
        "mfa_bypass_focus",
        "session_concurrency_focus",
        "geo_velocity_focus",
        "examples",
    ],
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run LANL/CERT Chimera benchmarks with research-oriented slice presets."
    )
    parser.add_argument("--input", required=True, help="Path to LANL/CERT auth.txt")
    parser.add_argument("--config", default="chimera.yaml", help="Base Chimera config")
    parser.add_argument("--limit", type=int, default=50000, help="Max streamed LANL events")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic injection seed")
    parser.add_argument("--magnitude", type=float, default=3.0, help="Injection magnitude")
    parser.add_argument(
        "--preset",
        choices=sorted(PRESET_SLICES),
        default="publishable_identity",
        help="Named report slice preset",
    )
    parser.add_argument(
        "--families",
        nargs="+",
        default=["session_hijack", "mfa_bypass", "password_spraying", "coordinated_campaign"],
        help="Attack families to benchmark in sequence",
    )
    parser.add_argument(
        "--output-dir",
        default="lanl_bench_suite",
        help="Directory for generated benchmark reports",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    output_dir = repo_root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    config = ChimeraConfig.load(repo_root / args.config)
    config.identity_research.enabled = True
    config.evaluation.report_slices = PRESET_SLICES[args.preset]

    temp_config = output_dir / "lanl_benchmark_config.json"
    config.save(temp_config)

    summaries: list[dict[str, object]] = []
    for family in args.families:
        family_out = output_dir / family
        command = [
            sys.executable,
            "-m",
            "chimera.cli",
            "bench-lanl",
            "--config",
            str(temp_config),
            "--input",
            str(args.input),
            "--limit",
            str(args.limit),
            "--injection-type",
            family,
            "--magnitude",
            str(args.magnitude),
            "--seed",
            str(args.seed),
            "--output",
            str(family_out),
        ]
        subprocess.run(command, cwd=repo_root, check=True)

        report_path = family_out / "bench_report.json"
        with report_path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)

        summaries.append(
            {
                "attack_family": family,
                "report": str(report_path),
                "lift_at_0_01_fpr": report.get("detection_lift_at_fpr", {}).get("0.01"),
                "takeover_only": report.get("benchmark_slices", {}).get("takeover_only", {}),
                "coordination_heavy": report.get("benchmark_slices", {}).get(
                    "coordination_heavy", {}
                ),
                "campaign_focus": report.get("benchmark_slices", {}).get(
                    "campaign_focus", {}
                ),
                "infra_reuse_heavy": report.get("benchmark_slices", {}).get(
                    "infra_reuse_heavy", {}
                ),
                "mfa_bypass_focus": report.get("benchmark_slices", {}).get(
                    "mfa_bypass_focus", {}
                ),
                "session_concurrency_focus": report.get("benchmark_slices", {}).get(
                    "session_concurrency_focus", {}
                ),
                "geo_velocity_focus": report.get("benchmark_slices", {}).get(
                    "geo_velocity_focus", {}
                ),
            }
        )

    summary_path = output_dir / "lanl_suite_summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "preset": args.preset,
                "families": args.families,
                "limit": args.limit,
                "seed": args.seed,
                "magnitude": args.magnitude,
                "summary": summaries,
            },
            handle,
            indent=2,
        )

    ReportGenerator(output_dir=output_dir).benchmark_suite_to_markdown(
        {
            "preset": args.preset,
            "families": args.families,
            "limit": args.limit,
            "seed": args.seed,
            "magnitude": args.magnitude,
            "summary": summaries,
        },
        prefix="lanl_suite",
    )

    print(summary_path)


if __name__ == "__main__":
    main()

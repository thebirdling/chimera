"""
Chimera CLI — Command-line interface for behavioral anomaly detection.

Commands:
    init        — Generate a starter configuration file
    train       — Train an anomaly detection model
    detect      — Detect anomalies in authentication logs
    report      — Generate reports from detection results
    rules       — List and validate detection rules
    correlate   — Run cross-user event correlation
    export      — Export results in SIEM formats (CEF, Syslog, STIX)
    baseline    — Build user behavior baselines
    watch       — Monitor a directory for new log files
    info        — Show model metadata
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import click

from chimera import __version__

logger = logging.getLogger("chimera")

_FIRE_BANNER = [
    r"   (  )   (   )  )",
    r"    ) (   )  (  (",
    r"    ( )  (    ) )",
    r"    _____________",
    r"   <_____________> ___",
    r"   |             |/ _ \\",
    r"   |   CHIMERA   | | | |",
    r"   |   v0.5.1    | |_| |",
    r"___|             |\\___/",
    r"/    \___________/    \\",
    r"\\_____________________/",
]

_FIRE_FRAMES = [
    " .  (  ) ",
    " .'. )(. ",
    " : .'.:  ",
    " '.: :'  ",
]


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt)


def _echo_header(title: str) -> None:
    """Print a styled header using rich if available, else plain."""
    try:
        from rich.console import Console
        from rich.panel import Panel

        Console().print(
            Panel(f"[bold cyan]{title}[/bold cyan]", border_style="blue")
        )
    except ImportError:
        click.echo(f"\n{'=' * 50}")
        click.echo(f"  {title}")
        click.echo(f"{'=' * 50}\n")


def _echo_brand_banner(title: str, subtitle: str = "") -> None:
    """Render Chimera's branded startup banner."""
    click.echo()
    for line in _FIRE_BANNER:
        click.echo(f"  {line}")
    click.echo(f"  {title}")
    if subtitle:
        click.echo(f"  {subtitle}")
    click.echo()


def _animate_stage(label: str, steps: int = 10, delay: float = 0.03) -> None:
    """Render a tiny ASCII loader without slowing normal CLI use too much."""
    if not sys.stdout.isatty():
        click.echo(f"[*] {label}...")
        return

    for idx in range(steps):
        frame = _FIRE_FRAMES[idx % len(_FIRE_FRAMES)]
        click.echo(f"\r{frame} {label}...", nl=False)
        time.sleep(delay)
    click.echo(f"\r[OK] {label}".ljust(len(label) + 12))


def _command_intro(title: str, subtitle: str = "") -> None:
    """Show a branded intro for interactive commands."""
    _echo_brand_banner(title, subtitle)
    _animate_stage("warming the furnace")


def _echo_table(headers: list[str], rows: list[list[str]], title: str = "") -> None:
    """Print a table using rich if available, else plain."""
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title=title, show_header=True, header_style="bold magenta")
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(*row)
        Console().print(table)
    except ImportError:
        if title:
            click.echo(f"\n{title}")
        widths = [max(len(h), *(len(r) for r in col)) for h, col in zip(headers, zip(*rows))] if rows else [len(h) for h in headers]
        header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
        click.echo(header_line)
        click.echo("-" * len(header_line))
        for row in rows:
            click.echo(" | ".join(c.ljust(w) for c, w in zip(row, widths)))


def _progress_bar(iterable, label: str = "Processing", length: int = 0):
    """Wrap an iterable in a progress bar."""
    try:
        from rich.progress import track
        return track(iterable, description=label, total=length or None)
    except ImportError:
        return click.progressbar(iterable, label=label, length=length)


def _load_detector_securely(model_path: str, config=None):
    from pathlib import Path

    from chimera.engine.integrity import IntegrityManifest
    from chimera.model import AnomalyDetector

    model_file = Path(model_path)
    manifest_path = model_file.parent / "integrity_manifest.json"
    integrity_enabled = True if config is None else getattr(config.integrity, "enabled", True)

    if manifest_path.exists():
        manifest = IntegrityManifest(manifest_path)
        return AnomalyDetector.load(model_file, manifest=manifest)

    if integrity_enabled:
        raise click.ClickException(
            "Refusing to load model without integrity verification. "
            f"Expected manifest at {manifest_path}."
        )

    return AnomalyDetector.load(model_file, allow_unverified=True)


def _feature_engineer_from_config(config):
    from chimera.feature_engineering import FeatureEngineer

    if config is None:
        return FeatureEngineer()

    return FeatureEngineer(
        max_history_days=config.features.max_history_days,
        enable_entropy=config.features.enable_entropy,
        enable_peer_group=config.features.enable_peer_group,
        enable_impossible_travel=config.features.enable_impossible_travel,
        enable_identity_research=getattr(config.identity_research, "enabled", False),
        identity_session_gap_minutes=getattr(
            config.identity_research, "session_gap_minutes", 45
        ),
        identity_burst_window_minutes=getattr(
            config.identity_research, "burst_window_minutes", 5
        ),
        identity_relation_window_minutes=getattr(
            config.identity_research, "relation_window_minutes", 15
        ),
        identity_max_shared_entity_users=getattr(
            config.identity_research, "max_shared_entity_users", 10
        ),
    )


def _scorer_from_config(config, threshold=None, contamination=None):
    from chimera.scoring import AnomalyScorer

    scoring_cfg = getattr(config, "scoring", None)
    identity_cfg = getattr(config, "identity_research", None)
    scorer_threshold = threshold if threshold is not None else getattr(scoring_cfg, "threshold", None)
    scorer_contamination = contamination if contamination is not None else getattr(scoring_cfg, "contamination", 0.1)
    identity_floor = None
    if (
        identity_cfg is not None
        and getattr(identity_cfg, "enabled", False)
        and getattr(identity_cfg, "scoring_hard_floor_enabled", False)
    ):
        identity_floor = getattr(identity_cfg, "takeover_hard_floor", 0.58)
    return AnomalyScorer(
        threshold=scorer_threshold,
        contamination=scorer_contamination,
        identity_hard_floor=identity_floor,
        identity_hard_floor_column="identity_takeover_score",
        identity_hard_floor_support_column="identity_takeover_support",
        identity_hard_floor_support_threshold=getattr(
            identity_cfg, "takeover_support_floor", 0.55
        ) if identity_cfg is not None else 0.55,
    )


def _inject_identity_raw_scores(raw_scores, features_df):
    research_columns = {
        "identity_sequence": "identity_sequence_score",
        "identity_relationship": "identity_relationship_score",
        "identity_fusion": "identity_fusion_score",
        "identity_campaign": "identity_campaign_score",
        "identity_password_spray": "identity_password_spray_score",
        "identity_low_and_slow": "identity_low_and_slow_score",
        "identity_takeover_sequence": "identity_takeover_sequence_score",
        "identity_takeover": "identity_takeover_score",
        "identity_takeover_support": "identity_takeover_support",
        "identity_mfa_bypass": "identity_mfa_bypass_suspicion",
    }
    for model_id, column in research_columns.items():
        if column in features_df.columns:
            raw_scores[model_id] = features_df[column].to_numpy(dtype=float)
    return raw_scores


def _identity_examples(results, limit: int = 5):
    examples = []
    ranked = sorted(
        [r for r in results if r.research_reasons],
        key=lambda r: (
            r.research_signals.get("identity_takeover_score", 0.0),
            r.research_signals.get("identity_fusion_score", 0.0),
        ),
        reverse=True,
    )
    for result in ranked[:limit]:
        examples.append(
            {
                "event_index": result.event_index,
                "user_id": result.user_id,
                "timestamp": result.timestamp.isoformat() if result.timestamp else None,
                "identity_fusion_score": result.research_signals.get(
                    "identity_fusion_score", 0.0
                ),
                "identity_takeover_score": result.research_signals.get(
                    "identity_takeover_score", 0.0
                ),
                "reasons": result.research_reasons[:3],
            }
        )
    return examples


def _benchmark_identity_examples(features_df, injected_test_events, ground_truth_mask, limit: int = 8):
    examples = []
    candidate_indices = [
        idx
        for idx, is_synth in enumerate(ground_truth_mask)
        if is_synth and idx < len(features_df)
    ]
    ranked = sorted(
        candidate_indices,
        key=lambda idx: (
            float(features_df.iloc[idx].get("identity_takeover_score", 0.0)),
            float(features_df.iloc[idx].get("identity_fusion_score", 0.0)),
            float(features_df.iloc[idx].get("identity_campaign_score", 0.0)),
            float(features_df.iloc[idx].get("identity_session_concurrency", 0.0)),
            float(features_df.iloc[idx].get("identity_geo_velocity_score", 0.0)),
        ),
        reverse=True,
    )
    for idx in ranked[:limit]:
        event = injected_test_events[idx]
        examples.append(
            {
                "event_index": idx,
                "user_id": event.user_id,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "session_id": event.session_id,
                "ip_address": event.ip_address,
                "country_code": event.country_code,
                "user_agent": event.user_agent,
                "identity_fusion_score": float(features_df.iloc[idx].get("identity_fusion_score", 0.0)),
                "identity_takeover_score": float(features_df.iloc[idx].get("identity_takeover_score", 0.0)),
                "identity_session_concurrency": float(features_df.iloc[idx].get("identity_session_concurrency", 0.0)),
                "identity_session_replay_burst": float(features_df.iloc[idx].get("identity_session_replay_burst", 0.0)),
                "identity_session_fingerprint_drift": float(features_df.iloc[idx].get("identity_session_fingerprint_drift", 0.0)),
                "identity_geo_velocity_score": float(features_df.iloc[idx].get("identity_geo_velocity_score", 0.0)),
                "identity_password_spray_score": float(features_df.iloc[idx].get("identity_password_spray_score", 0.0)),
                "identity_low_and_slow_score": float(features_df.iloc[idx].get("identity_low_and_slow_score", 0.0)),
                "identity_campaign_score": float(features_df.iloc[idx].get("identity_campaign_score", 0.0)),
                "identity_takeover_sequence_score": float(features_df.iloc[idx].get("identity_takeover_sequence_score", 0.0)),
                "identity_reasons": features_df.iloc[idx].get("identity_reasons", []),
            }
        )
    return examples


def _is_truthy_marker(value) -> bool:
    if value is True:
        return True
    if value in (False, None):
        return False
    if isinstance(value, float):
        try:
            import math

            if math.isnan(value):
                return False
        except Exception:
            return False
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def _slice_reports(
    train_scores,
    test_scores,
    features_df,
    ground_truth_mask,
    engine_config,
    requested_slices,
):
    from chimera.engine.pipeline import EnginePipeline
    import numpy as np
    import pandas as pd

    requested = set(requested_slices or [])
    if not requested:
        return {}

    train_ensemble = np.stack(list(train_scores.values()), axis=0).mean(axis=0)
    test_ensemble = np.stack(list(test_scores.values()), axis=0).mean(axis=0)
    baseline_threshold = float(np.percentile(train_ensemble, 95.0))
    baseline_mask = test_ensemble >= baseline_threshold

    pipeline = EnginePipeline.from_config(engine_config)
    pipeline.fit(train_scores)
    chimera_result = pipeline.score(test_scores, update_threshold=False)

    zeros = pd.Series(0.0, index=features_df.index)
    takeover_indicator = (
        features_df.get("identity_takeover_score", zeros).to_numpy(dtype=float) >= 0.50
    ) | (
        features_df.get("identity_takeover_support", zeros).to_numpy(dtype=float) >= 0.55
    )
    coordination_indicator = (
        features_df.get("identity_relationship_score", zeros).to_numpy(dtype=float) >= 0.20
    ) | (
        features_df.get("identity_sync_peer_count", zeros).to_numpy(dtype=float) >= 1.0
    ) | (
        features_df.get("identity_infra_burst_peer_count", zeros).to_numpy(dtype=float) >= 1.0
    ) | (
        features_df.get("identity_shared_ip_users", zeros).to_numpy(dtype=float) >= 1.0
    ) | (
        features_df.get("identity_shared_device_users", zeros).to_numpy(dtype=float) >= 1.0
    )
    infra_reuse_indicator = (
        features_df.get("identity_shared_infra_pair_users", zeros).to_numpy(dtype=float) >= 1.0
    ) | (
        features_df.get("identity_infra_burst_peer_count", zeros).to_numpy(dtype=float) >= 1.0
    )
    mfa_bypass_indicator = (
        features_df.get("identity_mfa_bypass_suspicion", zeros).to_numpy(dtype=float) >= 1.0
    )
    session_concurrency_indicator = (
        features_df.get("identity_session_concurrency", zeros).to_numpy(dtype=float) >= 0.5
    ) | (
        features_df.get("identity_session_replay_burst", zeros).to_numpy(dtype=float) >= 0.5
    ) | (
        features_df.get("identity_session_fingerprint_drift", zeros).to_numpy(dtype=float) >= 0.5
    )
    geo_velocity_indicator = (
        features_df.get("identity_geo_velocity_score", zeros).to_numpy(dtype=float) >= 0.5
    ) | (
        features_df.get("identity_geo_velocity_flag", zeros).to_numpy(dtype=float) >= 1.0
    ) | (
        features_df.get("identity_high_risk_country", zeros).to_numpy(dtype=float) >= 1.0
    )
    spray_indicator = (
        features_df.get("identity_password_spray_score", zeros).to_numpy(dtype=float) >= 0.5
    )
    low_and_slow_indicator = (
        features_df.get("identity_low_and_slow_score", zeros).to_numpy(dtype=float) >= 0.5
    )
    campaign_indicator = (
        features_df.get("identity_campaign_score", zeros).to_numpy(dtype=float) >= 0.5
    ) | coordination_indicator

    slice_masks = {}
    if "takeover_only" in requested:
        slice_masks["takeover_only"] = ground_truth_mask & takeover_indicator
    if "coordination_heavy" in requested:
        slice_masks["coordination_heavy"] = ground_truth_mask & coordination_indicator
    if "infra_reuse_heavy" in requested:
        slice_masks["infra_reuse_heavy"] = ground_truth_mask & infra_reuse_indicator
    if "mfa_bypass_focus" in requested:
        slice_masks["mfa_bypass_focus"] = ground_truth_mask & mfa_bypass_indicator
    if "session_concurrency_focus" in requested:
        slice_masks["session_concurrency_focus"] = ground_truth_mask & session_concurrency_indicator
    if "geo_velocity_focus" in requested:
        slice_masks["geo_velocity_focus"] = ground_truth_mask & geo_velocity_indicator
    if "spray_focus" in requested:
        slice_masks["spray_focus"] = ground_truth_mask & spray_indicator
    if "low_and_slow_focus" in requested:
        slice_masks["low_and_slow_focus"] = ground_truth_mask & low_and_slow_indicator
    if "campaign_focus" in requested:
        slice_masks["campaign_focus"] = ground_truth_mask & campaign_indicator

    reports = {}
    for slice_name, mask in slice_masks.items():
        n = int(mask.sum())
        if n == 0:
            reports[slice_name] = {"n_events": 0}
            continue
        reports[slice_name] = {
            "n_events": n,
            "baseline_detected_fraction": float((baseline_mask & mask).sum() / n),
            "chimera_detected_fraction": float((chimera_result.anomaly_mask & mask).sum() / n),
            "baseline_mean_score": float(np.mean(test_ensemble[mask])),
            "chimera_mean_score": float(np.mean(chimera_result.ensemble_scores[mask])),
            "chimera_hard_floor_hits": int(((chimera_result.ensemble_scores >= 1.0) & mask).sum()),
        }
    return reports


def _run_benchmark_workflow(
    *,
    config,
    events,
    injection_type,
    magnitude,
    seed,
    output_dir,
    click_module,
    dataset_label: str,
):
    import json
    import time
    from pathlib import Path

    from chimera.data_loader import AuthLogLoader
    from chimera.evaluation.injector import inject
    from chimera.evaluation.runner import run_benchmark
    from chimera.model import AnomalyDetector, ModelConfig
    import numpy as np
    import pandas as pd

    click_module.echo(f"  Events          : {len(events):,}")

    split = int(len(events) * 0.7)
    train_events = list(events[:split])
    test_events = list(events[split:])
    if len(train_events) < 30:
        raise ValueError(
            f"{dataset_label} benchmark needs at least 30 training events after the train/test split; "
            f"got {len(train_events)} from {len(events)} total events."
        )
    if not test_events:
        raise ValueError(
            f"{dataset_label} benchmark needs at least 1 test event after the train/test split."
        )
    test_records = [event.to_dict() for event in test_events]
    injected_records = inject(
        test_records,
        type=injection_type,
        magnitude=magnitude,
        window=config.evaluation.injection_window,
        seed=seed,
    )
    injected_test_events = AuthLogLoader().load_dataframe(pd.DataFrame(injected_records))
    ground_truth_mask = np.array(
        [
            _is_truthy_marker(getattr(event, "raw_fields", {}).get("_synthetic", False))
            for event in injected_test_events
        ],
        dtype=bool,
    )

    train_fe = _feature_engineer_from_config(config)
    train_features_df = train_fe.fit_transform(train_events)
    X_train = train_fe.get_numeric_features(train_features_df)

    test_features_df = train_fe.transform(injected_test_events)
    X_test = train_fe.get_numeric_features(test_features_df)

    train_scores: dict[str, np.ndarray] = {}
    test_scores: dict[str, np.ndarray] = {}
    for det_name in (config.model.ensemble_detectors or ["isolation_forest", "lof"]):
        if det_name == "isolation_forest":
            det_config = ModelConfig(
                n_estimators=config.model.n_estimators,
                contamination=config.model.contamination,
                scaler_type=config.model.scaler,
                n_jobs=1,
            )
            det = AnomalyDetector(det_config, detector_name=det_name)
        else:
            det = AnomalyDetector.from_registry(det_name)
        det.fit(X_train)
        train_scores[det_name] = np.asarray(det.score_samples(X_train))
        test_scores[det_name] = np.asarray(det.score_samples(X_test))

    train_scores = _inject_identity_raw_scores(train_scores, train_features_df)
    test_scores = _inject_identity_raw_scores(test_scores, test_features_df)

    click_module.echo("  Running benchmark (baseline vs Chimera)...")
    t0 = time.monotonic()
    engine_config = {
        "normalization": {"strategy": config.normalization.strategy},
        "ensemble": {
            "voting_strategy": "weighted",
            "weights": {
                "isolation_forest": 1.0,
                "lof": 1.0,
                "identity_sequence": 1.6,
                "identity_relationship": 1.8,
                "identity_fusion": 2.2,
                "identity_takeover": 3.2,
                "identity_takeover_support": 0.4,
                "identity_mfa_bypass": 1.8,
            },
        },
        "threshold": {"contamination": config.threshold.contamination},
        "identity_research": {
            "scoring_hard_floor_enabled": getattr(
                config.identity_research, "scoring_hard_floor_enabled", False
            ),
            "takeover_hard_floor": getattr(
                config.identity_research, "takeover_hard_floor", 0.58
            ),
            "takeover_support_floor": getattr(
                config.identity_research, "takeover_support_floor", 0.55
            ),
            "hard_floor_model": "identity_takeover",
            "hard_floor_support_model": "identity_takeover_support",
        },
    }

    bench_result = run_benchmark(
        raw_scores_train=train_scores,
        raw_scores_test=test_scores,
        events=[event.to_dict() for event in injected_test_events],
        ground_truth_mask=ground_truth_mask,
        injection_type=injection_type,
        injection_magnitude=magnitude,
        seed=seed,
        engine_config=engine_config,
    )
    elapsed = time.monotonic() - t0

    click_module.echo(f"\n  Benchmark complete in {elapsed:.2f}s\n")
    click_module.echo("  " + "-" * 62)
    for line in bench_result.summary_table().splitlines():
        click_module.echo("  " + line)
    click_module.echo("  " + "-" * 62)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    report_path = out_path / "bench_report.json"
    slice_reports = _slice_reports(
        train_scores=train_scores,
        test_scores=test_scores,
        features_df=test_features_df,
        ground_truth_mask=ground_truth_mask,
        engine_config=engine_config,
        requested_slices=config.evaluation.report_slices,
    )

    report_payload = {
        "dataset": dataset_label,
        "injection_type": bench_result.injection_type,
        "injection_magnitude": bench_result.injection_magnitude,
        "seed": bench_result.seed,
        "n_events_original": bench_result.n_events_original,
        "n_events_injected": bench_result.n_events_injected,
        "elapsed_seconds": bench_result.elapsed_seconds,
        "baseline": bench_result.baseline.to_dict(),
        "chimera": bench_result.chimera.to_dict(),
        "detection_lift_at_fpr": {
            str(fpr): bench_result.chimera.detection_rate_at_fpr.get(fpr, 0.0)
            - bench_result.baseline.detection_rate_at_fpr.get(fpr, 0.0)
            for fpr in bench_result.chimera.detection_rate_at_fpr
        },
        "benchmark_slices": slice_reports,
        "identity_examples": _benchmark_identity_examples(
            test_features_df,
            injected_test_events,
            ground_truth_mask,
        ),
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    from chimera.reporting import ReportGenerator
    report_generator = ReportGenerator(output_dir=out_path)
    benchmark_markdown_path = report_generator.benchmark_to_markdown(
        report_payload,
        prefix="bench",
    )

    click_module.echo(f"\n  Report saved to: {report_path}")
    click_module.echo(f"  Markdown       : {benchmark_markdown_path}")
    click_module.echo("\n[OK] chimera bench complete.")
    return report_path


# ── Main CLI group ───────────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="chimera")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=False),
    default=None,
    help="Path to chimera config file (YAML/JSON)",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config: Optional[str]) -> None:
    """Chimera — Behavioral Anomaly Detection for Authentication Logs"""
    _setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    if config:
        from chimera.config import ChimeraConfig

        try:
            ctx.obj["config"] = ChimeraConfig.load(config)
            logger.info(f"Loaded config from {config}")
        except Exception as e:
            logger.warning(f"Failed to load config: {e}. Using defaults.")
            ctx.obj["config"] = None
    else:
        ctx.obj["config"] = None


# ── init ─────────────────────────────────────────────────────────


@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="chimera.yaml",
    help="Output config file path",
)
def init(output: str) -> None:
    """Generate a starter configuration file with documented defaults."""
    from chimera.config import generate_default_config

    _command_intro("Chimera Init", "offline-first project bootstrap")
    path = generate_default_config(output)
    click.echo(f"[+] Default configuration generated at: {path}")
    click.echo("Edit this file to customize Chimera's behavior.")


# ── train ────────────────────────────────────────────────────────


@cli.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="chimera_model.joblib", help="Model output path")
@click.option("--contamination", type=float, default=None, help="Expected anomaly rate (0.0–0.5)")
@click.option("--n-estimators", type=int, default=None, help="Number of trees")
@click.option("--scaler", type=click.Choice(["standard", "robust"]), default=None)
@click.option("--detector", "-d", type=str, default=None, help="Detector name (isolation_forest, lof, ensemble)")
@click.pass_context
def train(
    ctx: click.Context,
    input_path: str,
    output: str,
    contamination: Optional[float],
    n_estimators: Optional[int],
    scaler: Optional[str],
    detector: Optional[str],
) -> None:
    """Train an anomaly detection model on authentication logs."""
    from chimera.data_loader import AuthLogLoader
    from chimera.feature_engineering import FeatureEngineer
    from chimera.model import AnomalyDetector, ModelConfig

    _command_intro("Chimera Train", "forging a detector from local authentication history")

    # Determine detector type
    cfg = ctx.obj.get("config")
    detector_name = detector or (cfg.model.detector if cfg else "isolation_forest")

    # Load data
    click.echo(f"[*] Loading data from {input_path}...")
    loader = AuthLogLoader()
    events = loader.load(input_path)
    click.echo(f"   Loaded {len(events)} events")

    # Feature engineering
    click.echo("[*] Engineering features...")
    engineer = _feature_engineer_from_config(cfg)
    features_df = engineer.fit_transform(events)
    numeric_features = engineer.get_numeric_features(features_df)
    click.echo(f"   Extracted {numeric_features.shape[1]} features")

    # Build and train detector
    click.echo(f"[*] Training {detector_name} model...")
    if detector_name == "isolation_forest":
        model_config = ModelConfig()
        if contamination is not None:
            model_config.contamination = contamination
        if n_estimators is not None:
            model_config.n_estimators = n_estimators
        if scaler:
            model_config.scaler_type = scaler
        model_config.n_jobs = 1
        det = AnomalyDetector(config=model_config, detector_name="isolation_forest")
    else:
        det = AnomalyDetector.from_registry(detector_name)

    det.fit(numeric_features, feature_names=engineer.get_feature_names())

    # Save
    manifest = None
    cfg = ctx.obj.get("config")
    if cfg is not None and getattr(cfg.integrity, "enabled", True):
        from chimera.engine.integrity import IntegrityManifest

        output_path = Path(output)
        manifest = IntegrityManifest(output_path.parent / "integrity_manifest.json")
    det.save(output, manifest=manifest)
    click.echo(f"[+] Model saved to {output}")

    # Summary
    if det.metadata:
        stats = det.metadata.training_stats
        click.echo(f"\n[=] Training summary:")
        click.echo(f"   Samples: {det.metadata.training_samples}")
        click.echo(f"   Features: {det.metadata.feature_count}")
        click.echo(f"   Score range: [{stats.get('score_min', 0):.4f}, {stats.get('score_max', 0):.4f}]")
        click.echo(f"   Estimated anomalies: {stats.get('estimated_anomalies', 'N/A')}")


# ── detect ───────────────────────────────────────────────────────


@cli.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.argument("model_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="chimera_results.json")
@click.option("--threshold", type=float, default=None, help="Manual anomaly threshold")
@click.option("--contamination", type=float, default=0.1, help="Auto-threshold contamination rate")
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "all"]), default="json")
@click.option("--rules/--no-rules", "use_rules", default=True, help="Enable/disable rule engine")
@click.pass_context
def detect(
    ctx: click.Context,
    input_path: str,
    model_path: str,
    output: str,
    threshold: Optional[float],
    contamination: float,
    fmt: str,
    use_rules: bool,
) -> None:
    """Detect anomalies in authentication logs using a trained model."""
    from chimera.data_loader import AuthLogLoader
    from chimera.feature_engineering import FeatureEngineer
    from chimera.model import AnomalyDetector
    from chimera.scoring import AnomalyScorer

    _command_intro("Chimera Detect", "scoring identity behavior against a trained local model")

    config = ctx.obj.get("config")

    # Load model
    click.echo(f"[*] Loading model from {model_path}...")
    detector = _load_detector_securely(model_path, config=config)

    # Load data
    click.echo(f"[*] Loading data from {input_path}...")
    loader = AuthLogLoader()
    events = loader.load(input_path)
    click.echo(f"   Loaded {len(events)} events")

    # Feature engineering
    click.echo("[*] Engineering features...")
    engineer = _feature_engineer_from_config(config)
    features_df = engineer.fit_transform(events)
    numeric_features = engineer.get_numeric_features(features_df)

    # ML scoring
    click.echo("[*] Scoring events...")
    scorer = _scorer_from_config(
        config,
        threshold=threshold,
        contamination=contamination,
    )
    results = scorer.score(events, features_df, detector)

    # Rule engine
    rule_matches = []
    if use_rules:
        click.echo("[*] Evaluating rules...")
        from chimera.rules.engine import RuleEngine

        engine = RuleEngine()
        engine.load_builtin_rules()
        rule_matches = engine.evaluate(events)
        click.echo(f"   {len(rule_matches)} rule matches found")

    # Generate user summaries
    user_summaries = scorer.summarize_by_user(results)

    # Save results
    anomaly_count = sum(1 for r in results if r.is_anomaly)
    click.echo(f"\n[?] Results: {anomaly_count} anomalies out of {len(results)} events")

    output_data = {
        "metadata": {
            "total_events": len(results),
            "anomaly_count": anomaly_count,
            "anomaly_rate": anomaly_count / max(len(results), 1),
            "rule_matches": len(rule_matches),
            "identity_research_enabled": bool(
                ctx.obj.get("config")
                and getattr(ctx.obj["config"].identity_research, "enabled", False)
            ),
        },
        "events": [r.to_dict() for r in results],
        "user_summaries": [s.to_dict() for s in user_summaries],
        "rule_matches": [m.to_dict() for m in rule_matches],
        "identity_examples": _identity_examples(results),
    }

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, default=str)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, default=str)

    click.echo(f"[+] Results saved to {output_path}")

    # Summary table
    if user_summaries:
        sorted_summaries = sorted(
            user_summaries, key=lambda s: s.anomaly_count, reverse=True
        )[:10]
        rows = [
            [
                s.user_id,
                str(s.total_events),
                str(s.anomaly_count),
                f"{s.anomaly_rate:.1%}",
                s.risk_level,
            ]
            for s in sorted_summaries
        ]
        _echo_table(
            ["User", "Events", "Anomalies", "Rate", "Risk"],
            rows,
            "Top Users by Anomaly Count",
        )


# ── report ───────────────────────────────────────────────────────


@cli.command()
@click.argument("results_path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["csv", "json", "markdown", "all"]), default="all")
@click.option("--output-dir", "-o", type=click.Path(), default="./chimera_reports")
@click.option("--prefix", type=str, default="chimera")
@click.pass_context
def report(
    ctx: click.Context,
    results_path: str,
    fmt: str,
    output_dir: str,
    prefix: str,
) -> None:
    """Generate reports from detection results."""
    from chimera.reporting import ReportGenerator
    from chimera.scoring import AnomalyResult, UserSummary

    _command_intro("Chimera Report", "shaping findings into analyst-ready artifacts")

    click.echo(f"[*] Loading results from {results_path}...")
    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    events = data.get("events", [])
    summaries = data.get("user_summaries", [])
    rule_matches = data.get("rule_matches", [])
    metadata = data.get("metadata", {})

    results = [AnomalyResult.from_dict(e) for e in events]

    user_summaries = []
    for s in summaries:
        user_summaries.append(UserSummary.from_dict(s))

    generator = ReportGenerator(output_dir=output_dir)

    score_distribution = metadata

    formats = ["csv", "json", "markdown"] if fmt == "all" else [fmt]

    generated: dict[str, Path] = {}
    for f in formats:
        if f == "csv":
            p = generator.to_csv_events(results, prefix=prefix)
            generated["csv_events"] = p
            if user_summaries:
                p2 = generator.to_csv_users(user_summaries, prefix=prefix)
                generated["csv_users"] = p2
        elif f == "json":
            p = generator.to_json(
                results, user_summaries, score_distribution, prefix=prefix
            )
            generated["json"] = p
        elif f == "markdown":
            p = generator.to_markdown(
                results,
                user_summaries,
                score_distribution,
                rule_matches=rule_matches,
                prefix=prefix,
            )
            generated["markdown"] = p

    click.echo(f"\n[+] Generated {len(generated)} report(s):")
    for name, path in generated.items():
        click.echo(f"   {name}: {path}")


# ── rules ────────────────────────────────────────────────────────


@cli.command()
@click.option("--list", "list_rules", is_flag=True, help="List all available rules")
@click.option("--test", "test_file", type=click.Path(exists=True), help="Test rules against a log file")
@click.pass_context
def rules(ctx: click.Context, list_rules: bool, test_file: Optional[str]) -> None:
    """List, validate, and test detection rules."""
    from chimera.rules.engine import RuleEngine

    _command_intro("Chimera Rules", "inspecting deterministic guardrails and comparisons")

    engine = RuleEngine()
    engine.load_builtin_rules()

    if list_rules or not test_file:
        all_rules = engine.list_rules()
        rows = [
            [r.id, r.name, r.severity, "[+]" if r.enabled else "[x]", ", ".join(r.tags)]
            for r in all_rules
        ]
        _echo_table(
            ["ID", "Name", "Severity", "Enabled", "Tags"],
            rows,
            f"{len(all_rules)} Detection Rules",
        )

    if test_file:
        from chimera.data_loader import AuthLogLoader

        click.echo(f"\n[*] Testing rules against {test_file}...")
        loader = AuthLogLoader()
        events = loader.load(test_file)
        matches = engine.evaluate(events)

        if matches:
            rows = [
                [
                    m.rule_id,
                    m.severity,
                    str(len(m.matched_events)),
                    ", ".join(m.matched_users[:3]),
                    m.description[:60],
                ]
                for m in matches
            ]
            _echo_table(
                ["Rule", "Severity", "Events", "Users", "Description"],
                rows,
                f"{len(matches)} Rule Matches",
            )
        else:
            click.echo("[+] No rule matches found.")


# ── correlate ────────────────────────────────────────────────────


@cli.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="chimera_correlations.json")
@click.option("--ip-window", type=int, default=30, help="IP correlation window (minutes)")
@click.option("--burst-window", type=int, default=5, help="Timing burst window (minutes)")
@click.option("--min-users", type=int, default=3, help="Minimum users for a cluster")
@click.pass_context
def correlate(
    ctx: click.Context,
    input_path: str,
    output: str,
    ip_window: int,
    burst_window: int,
    min_users: int,
) -> None:
    """Run cross-user event correlation analysis."""
    from chimera.data_loader import AuthLogLoader
    from chimera.correlator import EventCorrelator

    _command_intro("Chimera Correlate", "surfacing cross-user coordination and overlap")

    click.echo(f"[*] Loading data from {input_path}...")
    loader = AuthLogLoader()
    events = loader.load(input_path)
    click.echo(f"   Loaded {len(events)} events")

    click.echo("[*] Running correlation analysis...")
    correlator = EventCorrelator(
        ip_window_minutes=ip_window,
        burst_window_minutes=burst_window,
        min_users_for_cluster=min_users,
    )
    clusters = correlator.correlate(events)

    if clusters:
        rows = [
            [
                c.cluster_id,
                c.correlation_type,
                c.severity,
                str(len(c.events)),
                str(len(c.users)),
                c.description[:50],
            ]
            for c in clusters
        ]
        _echo_table(
            ["ID", "Type", "Severity", "Events", "Users", "Description"],
            rows,
            f"{len(clusters)} Correlation Clusters",
        )
    else:
        click.echo("[+] No correlation clusters found.")

    # Save
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(
            {"clusters": [c.to_dict() for c in clusters]},
            f,
            indent=2,
            default=str,
        )
    click.echo(f"[+] Correlations saved to {output_path}")


# ── export ───────────────────────────────────────────────────────


@cli.command("export")
@click.argument("results_path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["cef", "syslog", "stix", "all"]), default="all")
@click.option("--output-dir", "-o", type=click.Path(), default="./chimera_exports")
@click.option("--prefix", type=str, default="chimera")
@click.pass_context
def export_cmd(
    ctx: click.Context,
    results_path: str,
    fmt: str,
    output_dir: str,
    prefix: str,
) -> None:
    """Export results in SIEM-compatible formats (CEF, Syslog, STIX)."""
    from chimera.scoring import AnomalyResult
    from chimera.rules.engine import RuleMatch as RuleMatchDef
    from chimera.exporters import CEFExporter, SyslogExporter, STIXExporter

    _command_intro("Chimera Export", "packaging results for downstream security tooling")

    click.echo(f"[*] Loading results from {results_path}...")
    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = [AnomalyResult.from_dict(e) for e in data.get("events", [])]

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    formats = ["cef", "syslog", "stix"] if fmt == "all" else [fmt]
    generated = []

    for export_fmt in formats:
        if export_fmt == "cef":
            p = CEFExporter().export_results(results, out_dir / f"{prefix}.cef")
            generated.append(("CEF", p))
        elif export_fmt == "syslog":
            p = SyslogExporter().export_results(results, out_dir / f"{prefix}.syslog")
            generated.append(("Syslog", p))
        elif export_fmt == "stix":
            p = STIXExporter().export_results(results, out_dir / f"{prefix}.stix.json")
            generated.append(("STIX 2.1", p))

    click.echo(f"\n[+] Exported {len(generated)} format(s):")
    for name, path in generated:
        click.echo(f"   {name}: {path}")


# ── baseline ─────────────────────────────────────────────────────


@cli.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="chimera_baseline.json")
@click.pass_context
def baseline(ctx: click.Context, input_path: str, output: str) -> None:
    """Build user behavior baselines from historical data."""
    from chimera.data_loader import AuthLogLoader
    from chimera.feature_engineering import FeatureEngineer

    _command_intro("Chimera Baseline", "building local identity reference behavior")

    click.echo(f"[*] Loading data from {input_path}...")
    loader = AuthLogLoader()
    events = loader.load(input_path)
    click.echo(f"   Loaded {len(events)} events")

    click.echo("[*] Building user baselines...")
    engineer = _feature_engineer_from_config(ctx.obj.get("config"))
    engineer.fit(events)

    baselines = {}
    for uid, profile in engineer.user_profiles.items():
        baselines[uid] = {
            "user_id": uid,
            "total_events": profile.total_events,
            "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
            "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
            "failure_rate": round(profile.failure_rate, 4),
            "unique_ips": len(profile.known_ips),
            "unique_countries": len(profile.known_countries),
            "unique_devices": len(profile.known_devices) or len(profile.known_user_agents),
            "typical_hours": sorted(set(profile.typical_hours[-20:])),
            "typical_session_duration": profile.typical_session_duration,
            "known_auth_methods": sorted(profile.typical_auth_methods),
        }

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(baselines, f, indent=2, default=str)

    click.echo(f"[+] Baselines for {len(baselines)} users saved to {output_path}")

    rows = []
    for uid, b in sorted(baselines.items(), key=lambda x: x[1]["total_events"], reverse=True)[:10]:
        rows.append([
            uid,
            str(b["total_events"]),
            str(b["unique_ips"]),
            str(b["unique_countries"]),
            f"{b['failure_rate']:.1%}",
        ])

    if rows:
        _echo_table(
            ["User", "Events", "IPs", "Countries", "Fail Rate"],
            rows,
            "Top Users by Activity",
        )


# ── watch ────────────────────────────────────────────────────────


@cli.command()
@click.argument("watch_dir", type=click.Path(exists=True))
@click.argument("model_path", type=click.Path(exists=True))
@click.option("--interval", type=int, default=30, help="Poll interval in seconds")
@click.option("--pattern", type=str, default="*.csv", help="File glob pattern")
@click.option("--output-dir", "-o", type=click.Path(), default="./chimera_watch_results")
@click.pass_context
def watch(
    ctx: click.Context,
    watch_dir: str,
    model_path: str,
    interval: int,
    pattern: str,
    output_dir: str,
) -> None:
    """Monitor a directory for new log files and detect anomalies continuously."""
    from chimera.data_loader import AuthLogLoader
    from chimera.feature_engineering import FeatureEngineer
    from chimera.model import AnomalyDetector
    from chimera.scoring import AnomalyScorer

    _command_intro("Chimera Watch", "standing by for fresh authentication evidence")

    config = ctx.obj.get("config")

    click.echo(f"[*] Loading model from {model_path}...")
    detector = _load_detector_securely(model_path, config=config)

    watch_path = Path(watch_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    seen_files: set[str] = set()

    click.echo(f"[*]  Watching {watch_path} for {pattern} (every {interval}s)")
    click.echo("Press Ctrl+C to stop.\n")

    try:
        while True:
            new_files = []
            for f in watch_path.glob(pattern):
                if str(f) not in seen_files:
                    new_files.append(f)
                    seen_files.add(str(f))

            for log_file in new_files:
                click.echo(f"[+] New file detected: {log_file.name}")
                try:
                    loader = AuthLogLoader()
                    events = loader.load(log_file)

                    engineer = _feature_engineer_from_config(config)
                    features_df = engineer.fit_transform(events)
                    numeric = engineer.get_numeric_features(features_df)

                    scorer = _scorer_from_config(config)
                    results = scorer.score(events, features_df, detector)

                    anomalies = sum(1 for r in results if r.is_anomaly)
                    click.echo(
                        f"   -> {len(events)} events, "
                        f"{anomalies} anomalies detected"
                    )

                    result_path = out_path / f"{log_file.stem}_results.json"
                    with open(result_path, "w") as rf:
                        json.dump(
                            {"events": [r.to_dict() for r in results]},
                            rf,
                            indent=2,
                            default=str,
                        )
                except Exception as e:
                    click.echo(f"   [!]  Error processing {log_file.name}: {e}")

            time.sleep(interval)

    except KeyboardInterrupt:
        click.echo("\n[!] Watch stopped.")


# ── info ─────────────────────────────────────────────────────────


@cli.command()
@click.argument("model_path", type=click.Path(exists=True))
def info(model_path: str) -> None:
    """Show metadata about a trained model."""
    _command_intro("Chimera Model Info", "inspecting a verified local detector artifact")

    detector = _load_detector_securely(model_path, config=None)
    info_data = detector.get_model_info()

    for key, value in info_data.items():
        if isinstance(value, dict):
            click.echo(f"\n  {key}:")
            for k, v in value.items():
                click.echo(f"    {k}: {v}")
        else:
            click.echo(f"  {key}: {value}")


# ── run ──────────────────────────────────────────────────────────


@cli.command("run")
@click.option(
    "--config", "-c",
    "config_path",
    default="chimera.yaml",
    show_default=True,
    type=click.Path(exists=True),
    help="Path to Chimera YAML/JSON config file.",
)
@click.option(
    "--input", "-i",
    "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Path to authentication log file (CSV or JSON).",
)
@click.option(
    "--model", "-m",
    "model_path",
    default=None,
    type=click.Path(),
    help="Path to trained model (.joblib). If absent, trains in-situ on the input.",
)
@click.option(
    "--output", "-o",
    "output_dir",
    default="./chimera_output",
    show_default=True,
    type=click.Path(),
    help="Directory for detection output and robustness report.",
)
@click.pass_context
def run_cmd(
    ctx: click.Context,
    config_path: str,
    input_path: str,
    model_path: Optional[str],
    output_dir: str,
) -> None:
    """Run the full v0.5.1 engine pipeline from a config file.

    Loads the config, runs feature engineering, fits the normalization
    engine (or loads a pre-trained one), scores all events using the
    ensemble voter + dynamic threshold, and writes a robustness report.

    \b
    Example:
        chimera run --config chimera.yaml --input auth.csv --output ./results
    """
    import json
    import time
    from pathlib import Path

    _command_intro("Chimera v0.5.1 Run", "structured identity-behavior reasoning in motion")

    # 1. Load config
    try:
        from chimera.config import ChimeraConfig
        config = ChimeraConfig.load(config_path)
        click.echo(f"  Config     : {config_path}")
        click.echo(f"  Seed       : {config.seed}")
    except Exception as e:
        click.echo(f"ERROR: Failed to load config: {e}", err=True)
        raise SystemExit(1)

    # 2. Load data
    click.echo(f"  Input      : {input_path}")
    try:
        from chimera.data_loader import DataLoader
        loader = DataLoader(config)
        events = loader.load(input_path)
        click.echo(f"  Events     : {len(events):,}")
    except Exception as e:
        click.echo(f"ERROR: Failed to load data: {e}", err=True)
        raise SystemExit(1)

    if len(events) < 60:
        click.echo("WARNING: Fewer than 60 events — normalizer requires 30+ per model.", err=True)

    # 3. Feature engineering
    click.echo("  Engineering features...")
    try:
        import numpy as np
        fe = _feature_engineer_from_config(config)
        features_df = fe.fit_transform(events)
        X = fe.get_numeric_features(features_df)
        click.echo(f"  Features   : {X.shape[1]} dimensions, {X.shape[0]} samples")
    except Exception as e:
        click.echo(f"ERROR: Feature engineering failed: {e}", err=True)
        raise SystemExit(1)

    # 4. Per-model raw scores
    click.echo("  Scoring with detectors...")
    try:
        from chimera.model import AnomalyDetector, ModelConfig
        import numpy as np

        raw_scores: dict[str, np.ndarray] = {}
        detector_names = config.model.ensemble_detectors or ["isolation_forest", "lof"]

        for det_name in detector_names:
            if model_path:
                det = _load_detector_securely(model_path, config=config)
            else:
                if det_name == "isolation_forest":
                    det_config = ModelConfig(
                        n_estimators=config.model.n_estimators,
                        contamination=config.model.contamination,
                        scaler_type=config.model.scaler,
                        n_jobs=1,
                    )
                    det = AnomalyDetector(det_config, detector_name=det_name)
                else:
                    det = AnomalyDetector.from_registry(det_name)
                det.fit(X)

            scores = det.score_samples(X)
            raw_scores[det_name] = np.asarray(scores)
            click.echo(f"    {det_name}: mean={raw_scores[det_name].mean():.4f}")

        raw_scores = _inject_identity_raw_scores(raw_scores, features_df)
        if getattr(config.identity_research, "enabled", False):
            click.echo("    identity_research: additive sequence and relationship signals enabled")
    except Exception as e:
        click.echo(f"ERROR: Detector scoring failed: {e}", err=True)
        raise SystemExit(1)

    # 5. Engine pipeline (normalization → voting → threshold)
    click.echo("  Running engine pipeline...")
    try:
        from chimera.engine.pipeline import EnginePipeline

        engine_config = {
            "normalization": {
                "strategy": config.normalization.strategy,
                "low_variance_threshold": config.normalization.low_variance_threshold,
                "collapse_epsilon": config.normalization.collapse_epsilon,
                "quantile_range": config.normalization.quantile_range,
            },
            "ensemble": {
                "voting_strategy": config.ensemble_v3.voting_strategy,
                "trim_fraction": config.ensemble_v3.trim_fraction,
                "weights": config.ensemble_v3.weights,
            },
            "threshold": {
                "contamination": config.threshold.contamination,
                "recalc_window": config.threshold.recalc_window,
                "max_drift_history": config.threshold.max_drift_history,
            },
        }

        pipeline = EnginePipeline.from_config(engine_config)
        # In run mode: use the same data for fit and score (unsupervised, no labels)
        # For production, fit on historical data and score the new window.
        pipeline.fit(raw_scores)
        result = pipeline.score(raw_scores)

        n_anom = int(result.anomaly_mask.sum())
        click.echo(f"  Threshold  : {result.threshold:.6f}")
        click.echo(f"  Anomalies  : {n_anom:,} / {len(result.ensemble_scores):,} events "
                   f"({100.0 * n_anom / max(len(result.ensemble_scores), 1):.1f}%)")
        click.echo(f"  H(entropy) : {result.disagreement_entropy.mean():.4f} (mean inter-model disagreement)")
        click.echo(f"  Instability: {result.threshold_instability:.6f} (drift metric)")
    except Exception as e:
        click.echo(f"ERROR: Engine pipeline failed: {e}", err=True)
        raise SystemExit(1)

    # 6. Write output
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    report = {
        "threshold": result.threshold,
        "threshold_instability": result.threshold_instability,
        "n_events": len(result.ensemble_scores),
        "n_anomalies": n_anom,
        "disagreement_entropy_mean": float(result.disagreement_entropy.mean()),
        "score_variance_mean": float(result.score_variance.mean()),
        "anomaly_indices": [int(i) for i in np.where(result.anomaly_mask)[0]],
        "ensemble_scores": result.ensemble_scores.tolist(),
        "identity_research": {
            "enabled": bool(getattr(config.identity_research, "enabled", False)),
            "channels": [
                model_id
                for model_id in raw_scores
                if model_id.startswith("identity_")
            ],
            "examples": [
                {
                    "event_index": int(index),
                    "user_id": str(features_df.iloc[index]["user_id"]),
                    "identity_fusion_score": float(
                        features_df.iloc[index].get("identity_fusion_score", 0.0)
                    ),
                    "reasons": features_df.iloc[index].get("identity_reasons", []),
                }
                for index in np.where(result.anomaly_mask)[0][:5]
                if "identity_reasons" in features_df.columns
            ],
        },
    }

    report_path = out_path / "chimera_run_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    click.echo(f"\n  Report saved to: {report_path}")
    click.echo("\n[OK] chimera run complete.")


# ── bench ─────────────────────────────────────────────────────────


@cli.command("bench")
@click.option(
    "--config", "-c",
    "config_path",
    default="chimera.yaml",
    show_default=True,
    type=click.Path(exists=True),
    help="Path to Chimera YAML/JSON config file.",
)
@click.option(
    "--input", "-i",
    "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Path to authentication log file (CSV or JSON) for benchmarking.",
)
@click.option(
    "--injection-type",
    "injection_type",
    default="session_hijack",
    show_default=True,
    type=click.Choice(
        [
            "volume_spike",
            "temporal_shift",
            "credential_stuffing",
            "asn_shift",
            "burst_attack",
            "session_hijack",
            "mfa_bypass",
            "low_and_slow",
            "password_spraying",
            "coordinated_campaign",
            "identity_drift",
            "temporal_jitter",
        ],
        case_sensitive=False,
    ),
    help="Synthetic anomaly injection type for ground-truth evaluation.",
)
@click.option(
    "--magnitude",
    "magnitude",
    default=3.0,
    show_default=True,
    type=float,
    help="Injection intensity (interpretation varies by type).",
)
@click.option(
    "--seed",
    "seed",
    default=42,
    show_default=True,
    type=int,
    help="Random seed for deterministic injection.",
)
@click.option(
    "--output", "-o",
    "output_dir",
    default="./chimera_bench",
    show_default=True,
    type=click.Path(),
    help="Directory for benchmark report.",
)
@click.pass_context
def bench(
    ctx: click.Context,
    config_path: str,
    input_path: str,
    injection_type: str,
    magnitude: float,
    seed: int,
    output_dir: str,
) -> None:
    """Benchmark the v0.5.1 engine against a naive baseline using synthetic injection.

    Loads real events, injects synthetic anomalies for ground truth, then
    runs two pipelines side by side:
      - Baseline: raw mean of per-model scores, no normalization.
      - Chimera:  normalized → voted → dynamic threshold.

    Reports threshold drift, disagreement entropy, and detection rates at FPR.

    \b
    Example:
        chimera bench --config chimera.yaml --input auth.csv --injection-type burst_attack
    """
    import json
    import time
    from pathlib import Path

    _command_intro("Chimera v0.5.1 Benchmark", "measuring lift against controlled identity attacks")

    # Load config
    try:
        from chimera.config import ChimeraConfig
        config = ChimeraConfig.load(config_path)
    except Exception as e:
        click.echo(f"ERROR: Config load failed: {e}", err=True)
        raise SystemExit(1)

    click.echo(f"  Config          : {config_path}")
    click.echo(f"  Injection type  : {injection_type}  magnitude={magnitude}  seed={seed}")
    config.identity_research.enabled = True

    try:
        from chimera.data_loader import DataLoader

        loader = DataLoader(config)
        events = loader.load(input_path)
    except Exception as e:
        click.echo(f"ERROR: Data / feature load failed: {e}", err=True)
        raise SystemExit(1)
    try:
        _run_benchmark_workflow(
            config=config,
            events=events,
            injection_type=injection_type,
            magnitude=magnitude,
            seed=seed,
            output_dir=output_dir,
            click_module=click,
            dataset_label="generic_auth",
        )
    except Exception as e:
        click.echo(f"ERROR: Benchmark failed: {e}", err=True)
        raise SystemExit(1)


@cli.command("bench-lanl")
@click.option(
    "--config", "-c",
    "config_path",
    default="chimera.yaml",
    show_default=True,
    type=click.Path(exists=True),
    help="Path to Chimera YAML/JSON config file.",
)
@click.option(
    "--input", "-i",
    "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Path to LANL/CERT auth.txt file.",
)
@click.option(
    "--limit",
    default=50000,
    show_default=True,
    type=int,
    help="Maximum number of LANL auth events to stream into the benchmark.",
)
@click.option(
    "--injection-type",
    "injection_type",
    default="session_hijack",
    show_default=True,
    type=click.Choice(
        [
            "volume_spike",
            "temporal_shift",
            "credential_stuffing",
            "asn_shift",
            "burst_attack",
            "session_hijack",
            "mfa_bypass",
            "low_and_slow",
            "password_spraying",
            "coordinated_campaign",
            "identity_drift",
            "temporal_jitter",
        ],
        case_sensitive=False,
    ),
    help="Synthetic anomaly injection type for ground-truth evaluation.",
)
@click.option("--magnitude", default=3.0, show_default=True, type=float)
@click.option("--seed", default=42, show_default=True, type=int)
@click.option(
    "--output", "-o",
    "output_dir",
    default="./chimera_bench_lanl",
    show_default=True,
    type=click.Path(),
    help="Directory for benchmark report.",
)
def bench_lanl(
    config_path: str,
    input_path: str,
    limit: int,
    injection_type: str,
    magnitude: float,
    seed: int,
    output_dir: str,
) -> None:
    """Benchmark Chimera on a streamed slice of the LANL/CERT auth dataset."""
    _command_intro("Chimera v0.5.1 LANL Benchmark", "running publishable offline benchmark slices")
    try:
        from chimera.config import ChimeraConfig
        from chimera.data_loader import AuthLogLoader

        config = ChimeraConfig.load(config_path)
        config.identity_research.enabled = True
        loader = AuthLogLoader()
        events = list(loader.iter_lanl_auth(input_path, limit=limit))
    except Exception as e:
        click.echo(f"ERROR: LANL load failed: {e}", err=True)
        raise SystemExit(1)

    click.echo(f"  Config          : {config_path}")
    click.echo(f"  Input           : {input_path}")
    click.echo(f"  Limit           : {limit:,}")
    click.echo(f"  Injection type  : {injection_type}  magnitude={magnitude}  seed={seed}")

    try:
        _run_benchmark_workflow(
            config=config,
            events=events,
            injection_type=injection_type,
            magnitude=magnitude,
            seed=seed,
            output_dir=output_dir,
            click_module=click,
            dataset_label="lanl_auth",
        )
    except Exception as e:
        click.echo(f"ERROR: LANL benchmark failed: {e}", err=True)
        raise SystemExit(1)


# ── Entry point ──────────────────────────────────────────────────


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()

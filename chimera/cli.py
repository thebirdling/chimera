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

    _echo_header("Chimera Init")
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

    _echo_header("Chimera Train")

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
    engineer = FeatureEngineer()
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
        det = AnomalyDetector(config=model_config, detector_name="isolation_forest")
    else:
        det = AnomalyDetector.from_registry(detector_name)

    det.fit(numeric_features, feature_names=engineer.get_feature_names())

    # Save
    det.save(output)
    det.save(output)
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

    _echo_header("Chimera Detect")

    # Load model
    click.echo(f"[*] Loading model from {model_path}...")
    detector = AnomalyDetector.load(model_path)

    # Load data
    click.echo(f"[*] Loading data from {input_path}...")
    loader = AuthLogLoader()
    events = loader.load(input_path)
    click.echo(f"   Loaded {len(events)} events")

    # Feature engineering
    click.echo("[*] Engineering features...")
    engineer = FeatureEngineer()
    features_df = engineer.fit_transform(events)
    numeric_features = engineer.get_numeric_features(features_df)

    # ML scoring
    click.echo("[*] Scoring events...")
    scorer = AnomalyScorer(
        threshold=threshold,
        contamination=contamination,
    )
    results = scorer.score(events, numeric_features, detector)

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
        },
        "events": [r.to_dict() for r in results],
        "user_summaries": [s.to_dict() for s in user_summaries],
        "rule_matches": [m.to_dict() for m in rule_matches],
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

    _echo_header("Chimera Report")

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

    _echo_header("Chimera Rules")

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

    _echo_header("Chimera Correlate")

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

    _echo_header("Chimera Export")

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

    _echo_header("Chimera Baseline")

    click.echo(f"[*] Loading data from {input_path}...")
    loader = AuthLogLoader()
    events = loader.load(input_path)
    click.echo(f"   Loaded {len(events)} events")

    click.echo("[*] Building user baselines...")
    engineer = FeatureEngineer()
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

    _echo_header("Chimera Watch")

    click.echo(f"[*] Loading model from {model_path}...")
    detector = AnomalyDetector.load(model_path)

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

                    engineer = FeatureEngineer()
                    features_df = engineer.fit_transform(events)
                    numeric = engineer.get_numeric_features(features_df)

                    scorer = AnomalyScorer()
                    results = scorer.score(events, numeric, detector)

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
    from chimera.model import AnomalyDetector

    _echo_header("Chimera Model Info")

    detector = AnomalyDetector.load(model_path)
    info_data = detector.get_model_info()

    for key, value in info_data.items():
        if isinstance(value, dict):
            click.echo(f"\n  {key}:")
            for k, v in value.items():
                click.echo(f"    {k}: {v}")
        else:
            click.echo(f"  {key}: {value}")


# ── Entry point ──────────────────────────────────────────────────


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()

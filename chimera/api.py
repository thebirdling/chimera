"""
Portable programmatic runtime API for Chimera v0.6.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
import importlib
import json
import sys

import numpy as np
import pandas as pd

from chimera import __version__
from chimera.agent import review_artifact as review_artifact_agent, review_to_markdown
from chimera.cases import aggregate_identity_cases, summarize_case_detection
from chimera.config import ChimeraConfig
from chimera.contracts import (
    ArtifactRef,
    StableEnvelope,
    write_artifact_manifest,
    write_envelope,
)
from chimera.data_loader import AuthEvent, AuthLogLoader, DataLoader
from chimera.evaluation.injector import inject
from chimera.evaluation.runner import run_benchmark as eval_run_benchmark
from chimera.model import AnomalyDetector, ModelConfig
from chimera.reporting import ReportGenerator
from chimera.scoring import AnomalyResult, AnomalyScorer


REQUIRED_DEPENDENCIES = [
    "click",
    "pandas",
    "numpy",
    "scipy",
    "sklearn",
    "joblib",
    "yaml",
    "dateutil",
    "cryptography",
]


@dataclass
class DoctorCheck:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


def run_pipeline(
    *,
    config_path: str,
    input_path: str,
    model_path: Optional[str] = None,
    output_dir: str = "./chimera_output",
) -> StableEnvelope:
    """Run the full Chimera pipeline and return a stable envelope."""
    config = ChimeraConfig.load(config_path)
    loader = DataLoader(config)
    events = loader.load(input_path)

    feature_engineer = _feature_engineer_from_config(config)
    features_df = feature_engineer.fit_transform(events)
    feature_matrix = feature_engineer.get_numeric_features(features_df)

    raw_scores: dict[str, np.ndarray] = {}
    detector_names = config.model.ensemble_detectors or ["isolation_forest", "lof"]
    for detector_name in detector_names:
        detector = _load_or_fit_detector(
            detector_name=detector_name,
            feature_matrix=feature_matrix,
            config=config,
            model_path=model_path,
        )
        raw_scores[detector_name] = np.asarray(detector.score_samples(feature_matrix))

    raw_scores = _inject_identity_raw_scores(raw_scores, features_df)

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
    pipeline.fit(raw_scores)
    score_result = pipeline.score(raw_scores)

    anomaly_results = _build_runtime_results(
        events=events,
        features_df=features_df,
        scores=score_result.ensemble_scores,
        threshold=score_result.threshold,
        anomaly_mask=score_result.anomaly_mask,
    )
    cases = aggregate_identity_cases(
        anomaly_results,
        features_df=features_df,
        case_time_window_minutes=getattr(
            config.identity_research, "case_time_window_minutes", 30
        ),
    )

    payload = {
        "config_path": str(config_path),
        "input_path": str(input_path),
        "threshold": float(score_result.threshold),
        "threshold_instability": float(score_result.threshold_instability),
        "n_events": len(score_result.ensemble_scores),
        "n_anomalies": int(score_result.anomaly_mask.sum()),
        "disagreement_entropy_mean": float(score_result.disagreement_entropy.mean()),
        "score_variance_mean": float(score_result.score_variance.mean()),
        "anomaly_indices": [int(index) for index in np.where(score_result.anomaly_mask)[0]],
        "identity_research": {
            "enabled": bool(getattr(config.identity_research, "enabled", False)),
            "channels": [name for name in raw_scores if name.startswith("identity_")],
            "examples": _identity_examples(anomaly_results),
        },
        "cases": [case.to_dict() for case in cases],
        "case_summary": {
            "count": len(cases),
            "case_types": sorted({case.case_type for case in cases}),
        },
        "anomalous_events": [result.to_dict() for result in anomaly_results if result.is_anomaly],
    }
    envelope = StableEnvelope(command="run", payload=payload)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    report_path = write_envelope(out_path / "chimera_run_report.json", envelope)
    manifest_path = None
    if getattr(config.runtime_contract, "write_artifact_manifest", True):
        manifest_path = write_artifact_manifest(
            out_path,
            command_type="run",
            artifacts=[
                ArtifactRef(name="run_report", kind="json", relative_path=report_path.name),
            ],
        )
    envelope.payload["artifacts"] = {
        "report": str(report_path),
        "artifact_manifest": str(manifest_path) if manifest_path is not None else None,
    }
    write_envelope(report_path, envelope)
    return envelope


def run_benchmark(
    *,
    config_path: str,
    input_path: str,
    injection_type: str = "session_hijack",
    magnitude: float = 3.0,
    seed: int = 42,
    output_dir: str = "./chimera_bench",
    dataset_label: str = "generic_auth",
    limit: Optional[int] = None,
    lanl_mode: bool = False,
) -> StableEnvelope:
    """Run a stable benchmark envelope for generic or LANL auth data."""
    config = ChimeraConfig.load(config_path)
    config.identity_research.enabled = True

    if lanl_mode:
        loader = AuthLogLoader()
        events = list(loader.iter_lanl_auth(input_path, limit=limit or 50000))
    else:
        loader = DataLoader(config)
        events = loader.load(input_path)

    split = int(len(events) * 0.7)
    train_events = list(events[:split])
    test_events = list(events[split:])
    if len(train_events) < 30 or not test_events:
        raise ValueError("Benchmark requires at least 30 training events and 1 test event.")

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

    feature_engineer = _feature_engineer_from_config(config)
    train_features_df = feature_engineer.fit_transform(train_events)
    test_features_df = feature_engineer.transform(injected_test_events)
    train_matrix = feature_engineer.get_numeric_features(train_features_df)
    test_matrix = feature_engineer.get_numeric_features(test_features_df)

    train_scores: dict[str, np.ndarray] = {}
    test_scores: dict[str, np.ndarray] = {}
    for detector_name in (config.model.ensemble_detectors or ["isolation_forest", "lof"]):
        detector = _load_or_fit_detector(
            detector_name=detector_name,
            feature_matrix=train_matrix,
            config=config,
            model_path=None,
        )
        train_scores[detector_name] = np.asarray(detector.score_samples(train_matrix))
        test_scores[detector_name] = np.asarray(detector.score_samples(test_matrix))

    train_scores = _inject_identity_raw_scores(train_scores, train_features_df)
    test_scores = _inject_identity_raw_scores(test_scores, test_features_df)

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
                "identity_campaign": 2.0,
                "identity_password_spray": 1.8,
                "identity_low_and_slow": 1.8,
                "identity_takeover_sequence": 2.4,
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

    bench_result = eval_run_benchmark(
        raw_scores_train=train_scores,
        raw_scores_test=test_scores,
        events=[event.to_dict() for event in injected_test_events],
        ground_truth_mask=ground_truth_mask,
        injection_type=injection_type,
        injection_magnitude=magnitude,
        seed=seed,
        engine_config=engine_config,
    )

    case_results = _build_runtime_results(
        events=injected_test_events,
        features_df=test_features_df,
        scores=np.asarray(bench_result.chimera_ensemble_scores, dtype=float),
        threshold=float(bench_result.chimera_threshold),
        anomaly_mask=np.asarray(bench_result.chimera_anomaly_mask, dtype=bool),
    )
    cases = aggregate_identity_cases(
        case_results,
        features_df=test_features_df,
        case_time_window_minutes=getattr(
            config.identity_research, "case_time_window_minutes", 30
        ),
    )
    case_metrics = summarize_case_detection(
        cases,
        synthetic_event_indices={
            int(index) for index, is_synth in enumerate(ground_truth_mask) if is_synth
        },
        injection_type=injection_type,
    )

    from chimera.cli import _slice_reports, _benchmark_identity_examples

    slice_reports = _slice_reports(
        train_scores=train_scores,
        test_scores=test_scores,
        features_df=test_features_df,
        ground_truth_mask=ground_truth_mask,
        engine_config=engine_config,
        requested_slices=config.evaluation.report_slices,
    )

    payload = {
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
        "cases": [case.to_dict() for case in cases],
        "case_metrics": case_metrics,
    }
    envelope = StableEnvelope(
        command="bench-lanl" if lanl_mode else "bench",
        payload=payload,
    )

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    report_path = write_envelope(out_path / "bench_report.json", envelope)
    markdown_path = ReportGenerator(output_dir=out_path).benchmark_to_markdown(
        envelope.payload,
        prefix="bench",
    )
    manifest_path = None
    if getattr(config.runtime_contract, "write_artifact_manifest", True):
        manifest_path = write_artifact_manifest(
            out_path,
            command_type=envelope.command,
            artifacts=[
                ArtifactRef(name="bench_report", kind="json", relative_path=report_path.name),
                ArtifactRef(name="bench_markdown", kind="markdown", relative_path=markdown_path.name),
            ],
        )
    envelope.payload["artifacts"] = {
        "report": str(report_path),
        "markdown": str(markdown_path),
        "artifact_manifest": str(manifest_path) if manifest_path is not None else None,
    }
    write_envelope(report_path, envelope)
    return envelope


def inspect_model(model_path: str, *, config: Optional[ChimeraConfig] = None) -> StableEnvelope:
    """Return stable model metadata for a verified model artifact."""
    detector = _load_detector_securely(model_path, config=config)
    payload = {
        "model_path": str(model_path),
        "model_info": detector.get_model_info(),
        "integrity_manifest_present": (Path(model_path).parent / "integrity_manifest.json").exists(),
    }
    return StableEnvelope(command="info", payload=payload)


def detect_events(
    *,
    input_path: str,
    model_path: str,
    output_path: str,
    config: Optional[ChimeraConfig] = None,
    threshold: Optional[float] = None,
    contamination: float = 0.1,
    use_rules: bool = True,
) -> StableEnvelope:
    """Run stable detection flow for a trained model."""
    detector = _load_detector_securely(model_path, config=config)
    events = AuthLogLoader().load(input_path)
    engineer = _feature_engineer_from_config(config)
    features_df = engineer.fit_transform(events)
    scorer = _scorer_from_config(config, threshold=threshold, contamination=contamination)
    results = scorer.score(events, features_df, detector)
    user_summaries = scorer.summarize_by_user(results)

    rule_matches = []
    if use_rules:
        from chimera.rules.engine import RuleEngine

        engine = RuleEngine()
        engine.load_builtin_rules()
        rule_matches = engine.evaluate(events)

    cases = aggregate_identity_cases(
        results,
        features_df=features_df,
        case_time_window_minutes=getattr(
            config.identity_research, "case_time_window_minutes", 30
        ) if config is not None else 30,
    )
    anomaly_count = sum(1 for result in results if result.is_anomaly)
    payload = {
        "metadata": {
            "total_events": len(results),
            "anomaly_count": anomaly_count,
            "anomaly_rate": anomaly_count / max(len(results), 1),
            "rule_matches": len(rule_matches),
            "identity_research_enabled": bool(
                config and getattr(config.identity_research, "enabled", False)
            ),
        },
        "events": [result.to_dict() for result in results],
        "user_summaries": [summary.to_dict() for summary in user_summaries],
        "rule_matches": [match.to_dict() for match in rule_matches],
        "identity_examples": _identity_examples(results),
        "cases": [case.to_dict() for case in cases],
        "case_summary": {
            "count": len(cases),
            "case_types": sorted({case.case_type for case in cases}),
        },
    }
    envelope = StableEnvelope(command="detect", payload=payload)
    out_path = Path(output_path)
    report_path = write_envelope(out_path, envelope)
    manifest_path = None
    if config is None or getattr(config.runtime_contract, "write_artifact_manifest", True):
        manifest_path = write_artifact_manifest(
            out_path.parent,
            command_type="detect",
            artifacts=[
                ArtifactRef(name="detect_results", kind="json", relative_path=out_path.name),
            ],
        )
    envelope.payload["artifacts"] = {
        "report": str(report_path),
        "artifact_manifest": str(manifest_path) if manifest_path is not None else None,
    }
    write_envelope(out_path, envelope)
    return envelope


def doctor(
    *,
    config_path: Optional[str] = None,
    model_path: Optional[str] = None,
) -> StableEnvelope:
    """Return basic runtime diagnostics for Chimera packaging and embedding."""
    checks: list[DoctorCheck] = []
    checks.append(
        DoctorCheck(
            name="python_version",
            status="pass" if sys.version_info >= (3, 10) else "fail",
            detail=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
    )

    missing: list[str] = []
    for dependency in REQUIRED_DEPENDENCIES:
        try:
            importlib.import_module(dependency)
        except Exception:
            missing.append(dependency)
    checks.append(
        DoctorCheck(
            name="required_dependencies",
            status="pass" if not missing else "fail",
            detail="all required dependencies import cleanly" if not missing else f"missing: {', '.join(missing)}",
        )
    )

    from chimera._native import rust_graph

    native_state = {
        "graph_kernel": rust_graph.RUST_GRAPH_AVAILABLE,
        "burst_kernel": rust_graph.RUST_GRAPH_BURST_AVAILABLE,
        "burst_volume_kernel": rust_graph.RUST_GRAPH_BURST_VOLUME_AVAILABLE,
        "sequence_kernel": rust_graph.RUST_GRAPH_SEQUENCE_AVAILABLE,
    }
    native_any = any(native_state.values())
    checks.append(
        DoctorCheck(
            name="native_rust",
            status="pass",
            detail=(
                json.dumps(native_state)
                if native_any
                else "optional native kernels unavailable; Python fallbacks are active"
            ),
        )
    )

    try:
        from chimera.engine.integrity import IntegrityManifest  # noqa: F401

        integrity_status = "pass"
        integrity_detail = "integrity manifest support importable"
    except Exception as exc:
        integrity_status = "fail"
        integrity_detail = f"integrity imports failed: {exc}"
    checks.append(
        DoctorCheck(
            name="model_integrity_support",
            status=integrity_status,
            detail=integrity_detail,
        )
    )

    if config_path:
        try:
            ChimeraConfig.load(config_path)
            checks.append(
                DoctorCheck(
                    name="config_readability",
                    status="pass",
                    detail=f"loaded config: {config_path}",
                )
            )
        except Exception as exc:
            checks.append(
                DoctorCheck(
                    name="config_readability",
                    status="fail",
                    detail=f"failed to load {config_path}: {exc}",
                )
            )

    if model_path:
        try:
            _load_detector_securely(model_path)
            checks.append(
                DoctorCheck(
                    name="model_loadability",
                    status="pass",
                    detail=f"verified model load ok: {model_path}",
                )
            )
        except Exception as exc:
            checks.append(
                DoctorCheck(
                    name="model_loadability",
                    status="fail",
                    detail=f"model check failed: {exc}",
                )
            )

    try:
        event = AuthEvent(
            timestamp=pd.Timestamp("2026-01-01T00:00:00Z").to_pydatetime(),
            user_id="doctor@example.com",
            event_type="login",
            ip_address="203.0.113.10",
            success=True,
        )
        features = _feature_engineer_from_config(None).fit_transform([event])
        checks.append(
            DoctorCheck(
                name="runtime_health",
                status="pass",
                detail=f"feature pipeline ok with {features.shape[1]} columns",
            )
        )
    except Exception as exc:
        checks.append(
            DoctorCheck(
                name="runtime_health",
                status="fail",
                detail=f"feature pipeline failed: {exc}",
            )
        )

    overall = "pass"
    if any(check.status == "fail" for check in checks):
        overall = "fail"
    elif any(check.status == "warn" for check in checks):
        overall = "warn"

    payload = {
        "overall_status": overall,
        "checks": [check.to_dict() for check in checks],
        "chimera_version": __version__,
    }
    return StableEnvelope(command="doctor", payload=payload, status=overall)


def review_artifact(
    *,
    input_path: str,
    output_dir: Optional[str] = None,
) -> StableEnvelope:
    """Generate a deterministic local analyst review for a Chimera artifact."""
    envelope = review_artifact_agent(input_path)
    if output_dir is None:
        return envelope

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    report_path = write_envelope(out_path / "agent_review.json", envelope)
    markdown_path = out_path / "agent_review.md"
    markdown_path.write_text(
        review_to_markdown(envelope.payload.get("review", {})),
        encoding="utf-8",
    )
    manifest_path = write_artifact_manifest(
        out_path,
        command_type="agent-review",
        artifacts=[
            ArtifactRef(name="review", kind="json", relative_path=report_path.name),
            ArtifactRef(name="review_markdown", kind="markdown", relative_path=markdown_path.name),
        ],
    )
    envelope.payload.setdefault("artifacts", {})
    envelope.payload["artifacts"].update(
        {
            "report": str(report_path),
            "markdown": str(markdown_path),
            "artifact_manifest": str(manifest_path),
        }
    )
    write_envelope(report_path, envelope)
    return envelope


def _load_detector_securely(model_path: str, config: Optional[ChimeraConfig] = None) -> AnomalyDetector:
    from chimera.engine.integrity import IntegrityManifest
    from chimera.engine.exceptions import IntegrityError

    model_file = Path(model_path)
    manifest_path = model_file.parent / "integrity_manifest.json"
    integrity_enabled = True if config is None else getattr(config.integrity, "enabled", True)

    if manifest_path.exists():
        manifest = IntegrityManifest(manifest_path)
        return AnomalyDetector.load(model_file, manifest=manifest)

    if integrity_enabled:
        raise IntegrityError(
            "Refusing to load model without integrity verification. "
            f"Expected manifest at {manifest_path}."
        )
    return AnomalyDetector.load(model_file, allow_unverified=True)


def _load_or_fit_detector(
    *,
    detector_name: str,
    feature_matrix,
    config: ChimeraConfig,
    model_path: Optional[str],
) -> AnomalyDetector:
    if model_path:
        return _load_detector_securely(model_path, config=config)
    if detector_name == "isolation_forest":
        detector_config = ModelConfig(
            n_estimators=config.model.n_estimators,
            contamination=config.model.contamination,
            scaler_type=config.model.scaler,
            n_jobs=1,
        )
        detector = AnomalyDetector(detector_config, detector_name=detector_name)
    else:
        detector = AnomalyDetector.from_registry(detector_name)
    detector.fit(feature_matrix)
    return detector


def _feature_engineer_from_config(config: Optional[ChimeraConfig]):
    from chimera.feature_engineering import FeatureEngineer

    if config is None:
        return FeatureEngineer()
    return FeatureEngineer(
        max_history_days=config.features.max_history_days,
        enable_entropy=config.features.enable_entropy,
        enable_peer_group=config.features.enable_peer_group,
        enable_impossible_travel=config.features.enable_impossible_travel,
        enable_identity_research=getattr(config.identity_research, "enabled", False),
        identity_session_gap_minutes=getattr(config.identity_research, "session_gap_minutes", 45),
        identity_burst_window_minutes=getattr(config.identity_research, "burst_window_minutes", 5),
        identity_relation_window_minutes=getattr(config.identity_research, "relation_window_minutes", 15),
        identity_max_shared_entity_users=getattr(config.identity_research, "max_shared_entity_users", 10),
    )


def _scorer_from_config(
    config: Optional[ChimeraConfig],
    *,
    threshold: Optional[float] = None,
    contamination: Optional[float] = None,
) -> AnomalyScorer:
    scoring_cfg = getattr(config, "scoring", None)
    identity_cfg = getattr(config, "identity_research", None)
    scorer_threshold = threshold if threshold is not None else getattr(scoring_cfg, "threshold", None)
    scorer_contamination = (
        contamination if contamination is not None else getattr(scoring_cfg, "contamination", 0.1)
    )
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


def _inject_identity_raw_scores(raw_scores: dict[str, np.ndarray], features_df: pd.DataFrame):
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


def _build_runtime_results(
    *,
    events: list[AuthEvent],
    features_df: pd.DataFrame,
    scores: np.ndarray,
    threshold: float,
    anomaly_mask: np.ndarray,
) -> list[AnomalyResult]:
    results: list[AnomalyResult] = []
    for index, event in enumerate(events):
        score = float(scores[index])
        threshold_distance = abs(score - threshold)
        confidence = min(1.0, threshold_distance / max(abs(threshold), 0.1))
        row = features_df.iloc[index]
        results.append(
            AnomalyResult(
                event_index=index,
                user_id=event.user_id,
                timestamp=event.timestamp,
                event_type=event.event_type,
                anomaly_score=score,
                is_anomaly=bool(anomaly_mask[index]),
                confidence=float(confidence),
                research_signals=_extract_research_signals(row),
                research_reasons=list(row.get("identity_reasons", [])) if "identity_reasons" in features_df.columns else [],
                raw_event=event,
            )
        )
    return results


def _extract_research_signals(row: pd.Series) -> dict[str, float]:
    signals: dict[str, float] = {}
    for column, value in row.items():
        if column.startswith("identity_") and isinstance(value, (int, float, np.integer, np.floating)):
            signals[column] = float(value)
    return signals


def _identity_examples(results: list[AnomalyResult], limit: int = 5):
    ranked = sorted(
        [result for result in results if result.research_reasons],
        key=lambda result: (
            result.research_signals.get("identity_takeover_score", 0.0),
            result.research_signals.get("identity_fusion_score", 0.0),
        ),
        reverse=True,
    )
    return [
        {
            "event_index": result.event_index,
            "user_id": result.user_id,
            "timestamp": result.timestamp.isoformat() if result.timestamp else None,
            "identity_fusion_score": result.research_signals.get("identity_fusion_score", 0.0),
            "identity_takeover_score": result.research_signals.get("identity_takeover_score", 0.0),
            "reasons": result.research_reasons[:3],
        }
        for result in ranked[:limit]
    ]


def _is_truthy_marker(value) -> bool:
    if value is True:
        return True
    if value in (False, None):
        return False
    if isinstance(value, float):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "synthetic"}
    return bool(value)

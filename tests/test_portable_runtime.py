from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from chimera.api import detect_events, doctor, inspect_model, run_benchmark, run_pipeline
from chimera.cli import cli
from chimera.config import ChimeraConfig
from chimera.contracts import SCHEMA_VERSION
from chimera.engine.integrity import IntegrityManifest
from chimera.model import AnomalyDetector, ModelConfig


def _write_auth_csv(path: Path, n_events: int = 96) -> Path:
    path.write_text(
        "timestamp,user_id,event_type,ip_address,asn,country_code,user_agent,device_fingerprint,session_id,success\n"
        + "\n".join(
            f"2026-01-01T00:{i % 60:02d}:00Z,user{i % 6},"
            f"{'failed_login' if i % 9 == 0 else 'login'},"
            f"203.0.113.{(i % 4) + 1},AS6450{(i % 3)},US,ua-{i % 3},dev-{i % 5},sess-{i % 12},{'false' if i % 9 == 0 else 'true'}"
            for i in range(n_events)
        ),
        encoding="utf-8",
    )
    return path


def _write_config(path: Path) -> Path:
    config = ChimeraConfig()
    config.identity_research.enabled = True
    config.output.output_dir = str(path.parent / "out")
    config.save(path)
    return path


def _write_verified_model(csv_path: Path, model_dir: Path, config: ChimeraConfig | None = None) -> Path:
    from chimera.data_loader import AuthLogLoader
    from chimera.feature_engineering import FeatureEngineer

    events = AuthLogLoader().load(csv_path)
    if config is not None:
        engineer = FeatureEngineer(
            max_history_days=config.features.max_history_days,
            enable_peer_group=config.features.enable_peer_group,
            enable_entropy=config.features.enable_entropy,
            enable_impossible_travel=config.features.enable_impossible_travel,
            enable_identity_research=config.identity_research.enabled,
            identity_session_gap_minutes=config.identity_research.session_gap_minutes,
            identity_burst_window_minutes=config.identity_research.burst_window_minutes,
            identity_relation_window_minutes=config.identity_research.relation_window_minutes,
            identity_max_shared_entity_users=config.identity_research.max_shared_entity_users,
        )
    else:
        engineer = FeatureEngineer(enable_identity_research=True)
    features = engineer.fit_transform(events)
    numeric = engineer.get_numeric_features(features)
    detector = AnomalyDetector(ModelConfig(n_jobs=1))
    detector.fit(numeric)
    model_path = model_dir / "chimera_model.joblib"
    manifest = IntegrityManifest(model_dir / "integrity_manifest.json")
    detector.save(model_path, manifest=manifest)
    return model_path


def test_run_pipeline_contract_and_manifest(tmp_path):
    csv_path = _write_auth_csv(tmp_path / "auth.csv")
    config_path = _write_config(tmp_path / "chimera.json")

    envelope = run_pipeline(config_path=str(config_path), input_path=str(csv_path), output_dir=str(tmp_path / "run"))
    assert envelope.schema_version == SCHEMA_VERSION
    assert "cases" in envelope.payload
    manifest = json.loads((tmp_path / "run" / "artifact_manifest.json").read_text(encoding="utf-8"))
    assert manifest["command_type"] == "run"
    assert any(entry["relative_path"] == "chimera_run_report.json" for entry in manifest["generated_files"])


def test_detect_contract_and_info_and_doctor(tmp_path):
    csv_path = _write_auth_csv(tmp_path / "auth.csv")
    config_path = _write_config(tmp_path / "chimera.json")
    config = ChimeraConfig.load(config_path)
    model_path = _write_verified_model(csv_path, tmp_path / "model", config)

    envelope = detect_events(
        input_path=str(csv_path),
        model_path=str(model_path),
        output_path=str(tmp_path / "detect.json"),
        config=config,
    )
    assert envelope.schema_version == SCHEMA_VERSION
    assert "cases" in envelope.payload
    assert (tmp_path / "artifact_manifest.json").exists()

    info_env = inspect_model(str(model_path))
    assert info_env.command == "info"
    assert info_env.payload["integrity_manifest_present"] is True

    doctor_env = doctor(config_path=str(config_path), model_path=str(model_path))
    assert doctor_env.command == "doctor"
    assert doctor_env.payload["overall_status"] in {"pass", "warn"}


def test_benchmark_contract_contains_case_metrics(tmp_path):
    csv_path = _write_auth_csv(tmp_path / "auth.csv", n_events=120)
    config_path = _write_config(tmp_path / "chimera.json")

    envelope = run_benchmark(
        config_path=str(config_path),
        input_path=str(csv_path),
        injection_type="session_hijack",
        output_dir=str(tmp_path / "bench"),
    )
    assert envelope.schema_version == SCHEMA_VERSION
    assert "case_metrics" in envelope.payload
    assert (tmp_path / "bench" / "artifact_manifest.json").exists()


def test_cli_json_matches_api_run_summary(tmp_path):
    csv_path = _write_auth_csv(tmp_path / "auth.csv")
    config_path = _write_config(tmp_path / "chimera.json")
    api_env = run_pipeline(
        config_path=str(config_path),
        input_path=str(csv_path),
        output_dir=str(tmp_path / "api_run"),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "run",
            "--config",
            str(config_path),
            "--input",
            str(csv_path),
            "--output",
            str(tmp_path / "cli_run"),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    cli_env = json.loads(result.output)
    assert cli_env["schema_version"] == api_env.schema_version
    assert cli_env["payload"]["n_events"] == api_env.payload["n_events"]
    assert cli_env["payload"]["case_summary"]["count"] == api_env.payload["case_summary"]["count"]


def test_cli_info_and_doctor_json_contracts(tmp_path):
    csv_path = _write_auth_csv(tmp_path / "auth.csv")
    config_path = _write_config(tmp_path / "chimera.json")
    config = ChimeraConfig.load(config_path)
    model_path = _write_verified_model(csv_path, tmp_path / "model", config)

    runner = CliRunner()
    info_result = runner.invoke(cli, ["info", str(model_path), "--json"])
    assert info_result.exit_code == 0, info_result.output
    info_env = json.loads(info_result.output)
    assert info_env["command"] == "info"
    assert info_env["schema_version"] == SCHEMA_VERSION

    doctor_result = runner.invoke(
        cli,
        ["doctor", "--config", str(config_path), "--model", str(model_path), "--json"],
    )
    assert doctor_result.exit_code == 0, doctor_result.output
    doctor_env = json.loads(doctor_result.output)
    assert doctor_env["command"] == "doctor"
    assert doctor_env["schema_version"] == SCHEMA_VERSION

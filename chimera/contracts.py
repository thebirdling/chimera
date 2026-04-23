"""
Stable machine-facing runtime contracts for Chimera v0.6.0.

These contracts are intentionally small and versioned so future wrappers
can rely on them without scraping terminal output.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import json

from chimera import __version__

SCHEMA_VERSION = "1.0"


def utc_now_iso() -> str:
    """Return an RFC3339-friendly UTC timestamp string."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _jsonify(value: Any) -> Any:
    """Recursively convert dataclasses and Path objects to JSON-safe values."""
    if is_dataclass(value):
        return _jsonify(asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonify(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_jsonify(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonify(item) for item in value]
    return value


@dataclass
class ArtifactRef:
    """File emitted by a command that wrappers may want to consume."""

    name: str
    kind: str
    relative_path: str

    def to_dict(self) -> dict[str, Any]:
        return _jsonify(self)


@dataclass
class StableEnvelope:
    """Versioned command envelope used by CLI and programmatic APIs."""

    command: str
    payload: dict[str, Any]
    status: str = "ok"
    schema_version: str = SCHEMA_VERSION
    chimera_version: str = __version__
    generated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return _jsonify(self)


@dataclass
class ArtifactManifest:
    """Directory-level manifest of artifacts created by a Chimera command."""

    command_type: str
    generated_files: list[ArtifactRef]
    schema_version: str = SCHEMA_VERSION
    chimera_version: str = __version__
    generated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "chimera_version": self.chimera_version,
            "generated_at": self.generated_at,
            "command_type": self.command_type,
            "generated_files": [artifact.to_dict() for artifact in self.generated_files],
        }


def write_envelope(path: Path, envelope: StableEnvelope) -> Path:
    """Persist a stable envelope as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(envelope.to_dict(), handle, indent=2, default=str)
    return path


def write_artifact_manifest(
    output_dir: Path,
    *,
    command_type: str,
    artifacts: list[ArtifactRef],
) -> Path:
    """Write the stable artifact manifest for a command output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = ArtifactManifest(command_type=command_type, generated_files=artifacts)
    path = output_dir / "artifact_manifest.json"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest.to_dict(), handle, indent=2, default=str)
    return path


def unwrap_envelope(data: dict[str, Any]) -> dict[str, Any]:
    """Return the envelope payload when present, else the original mapping."""
    if isinstance(data, dict) and "schema_version" in data and "payload" in data:
        payload = data.get("payload")
        if isinstance(payload, dict):
            return payload
    return data

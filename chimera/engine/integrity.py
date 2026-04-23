"""
chimera.engine.integrity — SHA-256 + HMAC-protected artifact integrity.

Every trained model, config file, and state artifact is hash-verified
before use. On mismatch the load is refused and the event is logged at
CRITICAL level.

Security upgrades from v0.3
----------------------------
- **HMAC-protected manifest** (SEC-03): the manifest itself is signed with
  HMAC-SHA256. An adversary who has both modified a model file AND its hash
  in the manifest will still be caught because the manifest HMAC won't match.
- **Constant-time comparison** (SEC-11): ``hmac.compare_digest()`` replaces
  ``==`` to prevent timing oracle attacks on hash comparison.
- **Atomic manifest write**: random temp file + ``os.replace()`` to prevent
  partial writes on crash.
- **Machine-local key**: generated once per deployment into ``integrity.key``
  (mode 0o600). Defense deployments should bind this to a TPM or HSM.

Manifest format (``integrity_manifest.json``)
---------------------------------------------
```json
{
  "version": "2",
  "entries": { "<abs_path>": "<sha256_hex>" },
  "hmac": "<hmac_sha256_of_entries_hex>"
}
```

The HMAC is computed over the canonical JSON of the ``entries`` dict
(keys sorted, no extra whitespace) using the machine-local key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_MANIFEST_NAME = "integrity_manifest.json"
_KEY_NAME = "integrity.key"
_BACKUP_DIR = ".chimera_backups"
_BLOCK_SIZE = 65_536  # 64 KiB
_KEY_LEN = 32


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file. Streaming — safe for large models."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(_BLOCK_SIZE), b""):
            h.update(block)
    return h.hexdigest()


def _load_or_create_key(key_path: Path) -> bytes:
    """Load the HMAC key from disk, creating it if it doesn't exist."""
    if key_path.exists():
        key = key_path.read_bytes()
        if len(key) != _KEY_LEN:
            raise ValueError(f"Corrupt integrity key at {key_path}: expected {_KEY_LEN} bytes")
        return key
    # First-run: generate a new key
    key = secrets.token_bytes(_KEY_LEN)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    logger.info("[integrity] Generated new HMAC key → %s", key_path)
    return key


def _compute_manifest_hmac(key: bytes, entries: dict[str, str]) -> str:
    """Compute HMAC-SHA256 over the canonical JSON of entries (keys sorted)."""
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


class IntegrityManifest:
    """HMAC-protected manifest of SHA-256 digests for Chimera artifacts.

    Parameters
    ----------
    manifest_path:
        Path to the JSON manifest file (created on first save).
    key_path:
        Path to the HMAC key file. If not provided, defaults to
        ``<manifest_dir>/integrity.key``.
    """

    def __init__(
        self,
        manifest_path: str | Path,
        key_path: Optional[str | Path] = None,
    ) -> None:
        self.manifest_path = Path(manifest_path)
        if key_path is None:
            key_path = self.manifest_path.parent / _KEY_NAME
        self.key_path = Path(key_path)
        self._key_invalid = False
        try:
            self._key = _load_or_create_key(self.key_path)
        except ValueError as exc:
            logger.critical("[integrity] %s", exc)
            self._key = b"\x00" * _KEY_LEN
            self._key_invalid = True
        self._entries: dict[str, str] = {}
        self._load()

    # ------------------------------------------------------------------
    # Registration & verification
    # ------------------------------------------------------------------

    def register(self, artifact_path: str | Path, overwrite: bool = True) -> str:
        """Compute and store the SHA-256 digest for ``artifact_path``.

        Parameters
        ----------
        artifact_path:
            Path to the file to register.
        overwrite:
            If False and the path is already registered, raises ValueError.

        Returns
        -------
        str
            SHA-256 hex digest.
        """
        if self._key_invalid:
            raise ValueError(
                f"Integrity key is corrupt at {self.key_path}; refusing to register artifacts."
            )
        path = Path(artifact_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Cannot register missing file: {path}")

        key = str(path)
        if key in self._entries and not overwrite:
            raise ValueError(
                f"Artifact '{path}' is already registered. "
                "Use overwrite=True to update."
            )

        digest = sha256_file(path)
        self._entries[key] = digest
        self._save()
        logger.info("[integrity] Registered %s  sha256=%s…", path.name, digest[:16])
        return digest

    def verify(self, artifact_path: str | Path) -> tuple[bool, str]:
        """Verify that an artifact matches its registered digest.

        Uses ``hmac.compare_digest()`` for constant-time comparison to
        prevent timing oracle attacks.

        Returns
        -------
        tuple[bool, str]
            ``(ok, message)`` — True if the file matches its registered digest.
        """
        path = Path(artifact_path).resolve()
        key = str(path)

        if key not in self._entries:
            return False, f"No registered digest for '{path}'."

        if not path.exists():
            return False, f"Artifact missing: '{path}'."

        expected = self._entries[key]
        actual = sha256_file(path)

        # Constant-time comparison — prevents timing oracle attacks
        if hmac.compare_digest(actual, expected):
            logger.debug("[integrity] OK  %s", path.name)
            return True, f"OK: {path.name}"

        msg = (
            f"INTEGRITY VIOLATION: '{path.name}' digest mismatch! "
            f"expected={expected[:16]}… actual={actual[:16]}…"
        )
        logger.critical("[integrity] %s", msg)
        return False, msg

    def verify_manifest_hmac(self) -> bool:
        """Verify the manifest HMAC is intact.

        Returns False if the manifest was modified outside of Chimera
        (e.g. an attacker updated a hash to match a tampered model).
        """
        if self._key_invalid:
            logger.critical(
                "[integrity] Integrity key is corrupt or unreadable; manifest trust cannot be established."
            )
            return False
        if not self.manifest_path.exists():
            return True  # empty manifest is always valid
        try:
            raw = self.manifest_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:
            logger.critical("[integrity] Cannot parse manifest — file may be corrupted.")
            return False

        stored_hmac = data.get("hmac", "")
        entries = data.get("entries", {})
        expected_hmac = _compute_manifest_hmac(self._key, entries)

        if not hmac.compare_digest(stored_hmac, expected_hmac):
            logger.critical(
                "[integrity] MANIFEST HMAC VIOLATION — the integrity manifest "
                "itself has been tampered with. All artifact hashes are untrusted."
            )
            return False
        logger.debug("[integrity] Manifest HMAC OK.")
        return True

    def verify_all(self) -> dict[str, tuple[bool, str]]:
        """Verify every registered artifact. Returns dict of path → (ok, msg)."""
        results: dict[str, tuple[bool, str]] = {}
        for key in self._entries:
            ok, msg = self.verify(key)
            results[key] = (ok, msg)
        return results

    def require_valid(self, artifact_path: str | Path) -> None:
        """Verify an artifact and raise on failure.

        Also verifies the manifest HMAC before checking the artifact hash,
        so a tampered manifest is caught before any artifact check.
        """
        from chimera.engine.exceptions import IntegrityError
        if not self.verify_manifest_hmac():
            raise IntegrityError(
                "Integrity manifest HMAC failed — manifest may be tampered. "
                "Refusing to load any artifacts."
            )
        ok, msg = self.verify(artifact_path)
        if not ok:
            raise IntegrityError(f"Integrity check failed — refusing to load: {msg}")

    # ------------------------------------------------------------------
    # Backup & restore
    # ------------------------------------------------------------------

    def backup(self, artifact_path: str | Path) -> Path:
        """Copy ``artifact_path`` to the backup directory with a timestamp suffix."""
        src = Path(artifact_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Cannot back up missing file: {src}")
        backup_dir = src.parent / _BACKUP_DIR
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = int(time.time())
        dest = backup_dir / f"{src.stem}_{ts}{src.suffix}"
        shutil.copy2(src, dest)
        logger.info("[integrity] Backup: %s → %s", src.name, dest.name)
        return dest

    def restore_latest(self, artifact_path: str | Path) -> Optional[Path]:
        """Restore the most recently backed-up version of ``artifact_path``."""
        src = Path(artifact_path).resolve()
        backup_dir = src.parent / _BACKUP_DIR
        if not backup_dir.exists():
            logger.warning("[integrity] No backup directory for %s", src)
            return None
        candidates = sorted(
            backup_dir.glob(f"{src.stem}_*{src.suffix}"), reverse=True
        )
        if not candidates:
            logger.warning("[integrity] No backups found for %s", src.name)
            return None
        latest = candidates[0]
        shutil.copy2(latest, src)
        logger.info("[integrity] Restored %s from backup %s", src.name, latest.name)
        return latest

    # ------------------------------------------------------------------
    # Private: HMAC-protected persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        """Atomically save the manifest with a fresh HMAC signature."""
        if self._key_invalid:
            raise ValueError(
                f"Integrity key is corrupt at {self.key_path}; refusing to save manifest."
            )
        from chimera.engine.safe_io import atomic_write_text
        manifest_hmac = _compute_manifest_hmac(self._key, self._entries)
        data = {
            "version": "2",
            "entries": self._entries,
            "hmac": manifest_hmac,
        }
        serialized = json.dumps(data, indent=2)
        atomic_write_text(self.manifest_path, serialized, mode=0o600)

    def _load(self) -> None:
        """Load manifest from disk, verifying HMAC on load."""
        if not self.manifest_path.exists():
            return

        try:
            raw = self.manifest_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception as e:
            logger.critical("[integrity] Failed to parse manifest: %s", e)
            return

        # Handle legacy v1 manifests (no HMAC, plain dict of path→hash)
        if isinstance(data, dict) and "entries" not in data:
            logger.warning(
                "[integrity] Legacy v1 manifest detected — re-signing with HMAC. "
                "Run 'chimera integrity verify' to confirm all hashes are correct."
            )
            self._entries = data
            self._save()
            return

        stored_hmac = data.get("hmac", "")
        entries = data.get("entries", {})

        if self._key_invalid:
            self._entries = entries
            logger.critical(
                "[integrity] Loaded manifest entries without trust because the integrity key is corrupt."
            )
            return

        expected_hmac = _compute_manifest_hmac(self._key, entries)

        if stored_hmac and not hmac.compare_digest(stored_hmac, expected_hmac):
            logger.critical(
                "[integrity] MANIFEST HMAC MISMATCH on load — "
                "refusing to use potentially tampered manifest."
            )
            self._entries = {}
            return

        self._entries = entries
        logger.debug(
            "[integrity] Loaded HMAC-verified manifest with %d entries from %s",
            len(self._entries), self.manifest_path,
        )

    def __repr__(self) -> str:
        return (
            f"IntegrityManifest(entries={len(self._entries)}, "
            f"manifest={self.manifest_path.name!r}, "
            f"hmac_protected=True)"
        )

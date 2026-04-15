"""
chimera.engine.safe_io — Hardened file I/O primitives.

Provides three security primitives that replace all naive file operations
across Chimera:

1. **``safe_joblib_load``** — SHA-256 pre-verification before any joblib
   (pickle-based) deserialization. If the digest doesn't match, the file
   is never opened for deserialization. Prevents RCE from tampered models.

2. **``atomic_write``** — Write-to-random-temp + ``os.replace()`` with
   restrictive umask enforcement. Prevents partial writes, TOCTOU races,
   and world-readable artifact files.

3. **``safe_open_input``** — Canonicalizes paths and rejects any path that
   escapes outside a specified base directory. Prevents path traversal attacks.

Usage
-----
    # Instead of: payload = joblib.load(path)
    payload = safe_joblib_load(path, manifest)

    # Instead of: path.write_text(data)
    atomic_write(path, data.encode())

    # Instead of: open(user_supplied_path, "r")
    safe_open_input(user_supplied_path, base_dir="/var/chimera/data")
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from chimera.engine.integrity import IntegrityManifest

from chimera.engine.exceptions import IntegrityError

logger = logging.getLogger(__name__)

_BLOCK_SIZE = 65_536  # 64 KiB


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file. Streaming — safe for large models."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(_BLOCK_SIZE), b""):
            h.update(block)
    return h.hexdigest()


def safe_joblib_load(
    path: str | Path,
    manifest: Optional["IntegrityManifest"] = None,
    expected_digest: Optional[str] = None,
) -> Any:
    """Load a joblib file with SHA-256 pre-verification.

    The integrity check happens BEFORE any bytes of the file are passed to
    joblib/pickle. If verification fails, ``IntegrityError`` is raised and
    the file is never deserialized.

    Parameters
    ----------
    path:
        Path to the ``.joblib`` file.
    manifest:
        :class:`IntegrityManifest` instance. If provided, the file's digest
        is verified against the manifest. Takes precedence over
        ``expected_digest``.
    expected_digest:
        SHA-256 hex digest to verify against (used if no manifest is provided).
        If neither is provided, the file is loaded without verification and
        a WARNING is emitted.

    Returns
    -------
    Any
        Deserialized joblib payload.

    Raises
    ------
    IntegrityError:
        If digest verification fails.
    FileNotFoundError:
        If the file does not exist.
    """
    import joblib

    path = Path(path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Model file not found: {path}")

    if manifest is not None:
        ok, msg = manifest.verify(path)
        if not ok:
            raise IntegrityError(
                f"Refusing to load — integrity check failed: {msg}"
            )
        logger.debug("[safe_io] Integrity OK: %s", path.name)

    elif expected_digest is not None:
        actual = sha256_file(path)
        import hmac as _hmac
        if not _hmac.compare_digest(actual, expected_digest.lower()):
            raise IntegrityError(
                f"Digest mismatch for '{path.name}': "
                f"expected={expected_digest[:12]}… actual={actual[:12]}…"
            )
        logger.debug("[safe_io] Digest OK (manual): %s", path.name)

    else:
        logger.warning(
            "[safe_io] Loading '%s' WITHOUT integrity verification. "
            "This is UNSAFE in production — provide a manifest or expected_digest.",
            path.name,
        )

    return joblib.load(path)


def atomic_write(
    path: str | Path,
    data: bytes,
    mode: int = 0o600,
) -> None:
    """Write bytes atomically with restrictive file permissions.

    Algorithm:
    1. Set umask to 0o177 (only owner rw)
    2. Write to a random temp file in the same directory
    3. ``os.replace()`` (atomic on POSIX, best-effort on Windows)
    4. Restore umask

    Parameters
    ----------
    path:
        Destination path.
    data:
        Bytes to write.
    mode:
        Final file permission mode. Default 0o600 (owner read/write only).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Random suffix prevents TOCTOU collision with predictable temp names
    tmp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"

    old_mask = os.umask(0o177)
    try:
        tmp.write_bytes(data)
        # Set final permissions before replacing
        try:
            os.chmod(tmp, mode)
        except (AttributeError, NotImplementedError):
            pass  # Windows does not support full chmod; no-op
        os.replace(tmp, path)
    except Exception:
        # Clean up temp file on failure
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    finally:
        os.umask(old_mask)

    logger.debug("[safe_io] Atomic write: %s (%d bytes)", path, len(data))


def atomic_write_text(
    path: str | Path,
    text: str,
    encoding: str = "utf-8",
    mode: int = 0o600,
) -> None:
    """Convenience wrapper: encode text and write atomically."""
    atomic_write(path, text.encode(encoding), mode=mode)


def atomic_sync_write(
    path: str | Path,
    data: bytes,
    mode: int = 0o600,
) -> None:
    """Defense-Grade: Atomic write with immediate redundancy mirror (.bak)."""
    path = Path(path)
    bak_path = path.with_suffix(path.suffix + ".bak")
    
    # Write primary
    atomic_write(path, data, mode=mode)
    # Write mirror
    atomic_write(bak_path, data, mode=mode)


def atomic_sync_write_text(
    path: str | Path,
    text: str,
    encoding: str = "utf-8",
    mode: int = 0o600,
) -> None:
    """Defense-Grade: Atomic text write with redundancy mirror."""
    atomic_sync_write(path, text.encode(encoding), mode=mode)


def load_with_fallback(path: str | Path, force_backup: bool = False) -> bytes:
    """Defense-Grade: Load primary file with automatic fallback to .bak mirror.

    If the primary file is missing, unreadable, or otherwise inaccessible, 
    the system attempts to retrieve state from the redundant backup.
    
    If force_backup=True, the primary is skipped entirely (useful when the
    caller has already determined the primary content is corrupt).
    """
    path = Path(path)
    bak_path = path.with_suffix(path.suffix + ".bak")

    errors = []
    # Try primary
    if not force_backup and path.exists():
        try:
            return path.read_bytes()
        except OSError as e:
            errors.append(f"primary({e})")

    # Try backup
    if bak_path.exists():
        if not force_backup:
            logger.critical(
                "[safe_io] PRIMARY STATE CORRUPT or missing: %s. "
                "Engaging FAIL-SAFE REDUNDANCY: loading from %s.",
                path.name, bak_path.name
            )
        try:
            return bak_path.read_bytes()
        except OSError as e:
            errors.append(f"backup({e})")

    err_msg = f"Inaccessible state: {path}"
    if errors:
        err_msg += f" (Errors: {', '.join(errors)})"
    raise FileNotFoundError(err_msg)


def safe_open_input(
    path: str | Path,
    base_dir: Optional[str | Path] = None,
) -> Path:
    """Canonicalize and safety-check a user-supplied input path.

    Parameters
    ----------
    path:
        Path to validate.
    base_dir:
        If provided, the resolved path must be inside this directory.
        Pass the data directory or config directory to prevent traversal.

    Returns
    -------
    Path
        Resolved, canonicalized path.

    Raises
    ------
    ValueError:
        If the path escapes ``base_dir`` (path traversal) or contains
        null bytes.
    FileNotFoundError:
        If the file doesn't exist.
    """
    raw = str(path)

    # Null byte injection guard
    if "\x00" in raw:
        raise ValueError("Null byte in path — possible injection attempt.")

    resolved = Path(path).resolve()

    if base_dir is not None:
        base = Path(base_dir).resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            raise ValueError(
                f"Path traversal rejected: '{resolved}' is outside "
                f"base directory '{base}'."
            )

    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")

    return resolved

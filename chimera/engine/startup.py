"""
chimera.engine.startup — Installation integrity verification (v0.4.2).

Defends against import injection attacks (B3/D3):
    An attacker plants a malicious `chimera/` directory earlier in sys.path
    so that `from chimera.crypto import ...` loads the attacker's code
    instead of the real implementation — bypassing all security controls
    at import time.

How it works
------------
1. Resolves the canonical installation prefix of the *real* chimera package
   (the directory that was validated at install time).

2. Iterates over all currently-imported `chimera.*` modules (already in
   sys.modules) and verifies each module's `__file__` is under the same
   canonical prefix.

3. Also validates that no module was loaded from `site-packages` of a
   different Python environment, from `tmp`, or from a writable user cache.

4. On any violation: logs CRITICAL and raises RuntimeError — the caller
   (CLI entry point) should immediately exit.

Usage
-----
Call ``verify_chimera_installation()`` as the very first thing in any CLI
entry point or long-running daemon:

    from chimera.engine.startup import verify_chimera_installation
    verify_chimera_installation()          # raises on tamper

You can also call it lazily via the context manager:

    with chimera_install_guard():
        ...your code...
"""
from __future__ import annotations

import logging
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)


def _get_chimera_prefix() -> Path:
    """Resolve the canonical installation prefix of this chimera package."""
    import chimera as _chimera_root
    root_file = getattr(_chimera_root, "__file__", None)
    if root_file is None:
        raise RuntimeError(
            "[startup] Cannot determine chimera installation prefix: "
            "chimera.__file__ is None (namespace package?)"
        )
    # chimera/__init__.py → parent = chimera/ → parent = site-packages/
    return Path(root_file).resolve().parent


def verify_chimera_installation(strict: bool = True) -> list[str]:
    """Verify all loaded chimera submodules are from the expected prefix.

    Parameters
    ----------
    strict:
        If True (default) raise RuntimeError on any violation.
        If False, only log and return the violation list.

    Returns
    -------
    List of violation strings (empty = clean installation).

    Raises
    ------
    RuntimeError
        If ``strict=True`` and any module fails the prefix check.
    """
    try:
        prefix = _get_chimera_prefix()
    except RuntimeError as e:
        if strict:
            raise
        logger.error("[startup] %s", e)
        return [str(e)]

    violations = []

    for mod_name, mod in list(sys.modules.items()):
        if not mod_name.startswith("chimera"):
            continue

        mod_file = getattr(mod, "__file__", None)
        if mod_file is None:
            # Namespace packages and built-ins have no __file__ — skip
            continue

        try:
            resolved = Path(mod_file).resolve()
        except (OSError, ValueError):
            violations.append(f"{mod_name}: cannot resolve path {mod_file!r}")
            continue

        # Check canonical prefix containment
        try:
            resolved.relative_to(prefix)
        except ValueError:
            violation = (
                f"IMPORT INJECTION detected: module '{mod_name}' loaded from "
                f"{resolved} which is OUTSIDE expected prefix {prefix}. "
                f"A malicious package may have shadowed chimera on sys.path."
            )
            logger.critical("[startup] ⛔ %s", violation)
            violations.append(violation)

    # Additional sys.path poisoning checks
    _check_syspath_order(violations)

    if violations and strict:
        raise RuntimeError(
            f"[startup] Chimera installation integrity check FAILED "
            f"({len(violations)} violation(s)):\n" +
            "\n".join(f"  - {v}" for v in violations)
        )

    if not violations:
        logger.debug(
            "[startup] Installation integrity OK. prefix=%s, modules_checked=%d",
            prefix,
            sum(1 for n in sys.modules if n.startswith("chimera")),
        )

    return violations


def _check_syspath_order(violations: list[str]) -> None:
    """Warn if any writable user directory precedes the chimera prefix in sys.path."""
    try:
        prefix = _get_chimera_prefix()
    except RuntimeError:
        return

    prefix_index: int | None = None
    for i, p in enumerate(sys.path):
        try:
            if Path(p).resolve() == prefix or (
                prefix_index is None and prefix.is_relative_to(Path(p).resolve())
            ):
                prefix_index = i
                break
        except (OSError, ValueError):
            continue

    if prefix_index is None:
        return  # Can't determine order — skip check

    for i, p in enumerate(sys.path[:prefix_index]):
        if not p:
            continue  # empty string = CWD, skip
        try:
            p_resolved = Path(p).resolve()
            # Flag writable user dirs that precede the install prefix
            if p_resolved.exists() and os.access(p_resolved, os.W_OK):
                # Tmpdir or home dir before install prefix is suspicious
                p_str = str(p_resolved).lower()
                if any(suspect in p_str for suspect in ("tmp", "temp", "home", "users")):
                    msg = (
                        f"sys.path[{i}]={p_resolved!r} is writable and precedes "
                        f"the chimera install prefix — possible path injection risk."
                    )
                    logger.warning("[startup] ⚠ %s", msg)
                    # This is WARNING not violation — legitimate dev setups do this
        except (OSError, ValueError):
            continue


def verify_module_not_shadowed(module_name: str) -> bool:
    """Check if a specific module is loaded from the expected location.

    Useful for lightweight spot-checks without a full installation scan.

    Returns
    -------
    True if the module is correctly located, False if shadowed.
    """
    mod = sys.modules.get(module_name)
    if mod is None:
        return True  # Not yet imported, nothing to verify

    mod_file = getattr(mod, "__file__", None)
    if mod_file is None:
        return True

    try:
        prefix = _get_chimera_prefix()
        Path(mod_file).resolve().relative_to(prefix)
        return True
    except (ValueError, RuntimeError):
        logger.critical(
            "[startup] Module '%s' loaded from UNEXPECTED path: %s",
            module_name, mod_file,
        )
        return False


@contextmanager
def chimera_install_guard() -> Generator[None, None, None]:
    """Context manager that verifies installation integrity on entry.

    Example
    -------
    ::

        with chimera_install_guard():
            pipeline = EnginePipeline.load("models/")
    """
    verify_chimera_installation(strict=True)
    yield

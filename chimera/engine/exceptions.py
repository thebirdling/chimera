"""
chimera.engine.exceptions — Shared exception hierarchy.

All Chimera-specific exceptions inherit from ChimeraError, allowing callers
to catch the entire hierarchy with a single ``except ChimeraError``.

Using a single module for exceptions prevents the dual-definition problem
where normalizer.InsufficientDataError and threshold.InsufficientDataError
are separate classes that cannot be caught by the same handler.
"""
from __future__ import annotations


class ChimeraError(Exception):
    """Base class for all Chimera-specific exceptions."""


class InsufficientDataError(ChimeraError, ValueError):
    """Raised when fewer samples than the required minimum are provided.

    Inherits from both ChimeraError (for Chimera-specific catching) and
    ValueError (for standard Python convention — bad argument value).
    """


class NotFittedError(ChimeraError, RuntimeError):
    """Raised when a component is used before fit() has been called.

    Replaces ad-hoc RuntimeError("Call fit() first.") strings throughout
    the codebase with a typed, catchable exception.
    """


class IntegrityError(ChimeraError, RuntimeError):
    """Raised when an integrity check fails (hash mismatch, missing artifact).

    Used by IntegrityManifest.require_valid() to refuse loading
    tampered or corrupted model files.
    """


class BootstrapPhaseError(ChimeraError, RuntimeError):
    """Raised when an operation is attempted in the wrong bootstrap phase.

    For example: requesting anomaly scores during the OBSERVE phase,
    before any model has been fitted.
    """

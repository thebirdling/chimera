"""
chimera.experimental — Optional, sandboxed experimental modules.

These modules implement research-grade extensions that are NOT part of the
core detection pipeline. They require additional dependencies and must be
explicitly enabled via the config (``experimental.topology.enabled: true``).

If dependencies are unavailable, all modules degrade gracefully and emit
an informative ImportError-style warning — they never break core detection.

Current experimental modules
-----------------------------
topology    Vietoris-Rips persistent homology + Betti-0/1 extraction.
            Requires: gudhi >= 3.8, scipy, scikit-learn.
"""

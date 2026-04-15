"""
chimera.experimental.topology — Topological Data Analysis (TDA) sandbox.

Implements Persistent Homology on behavioral feature vectors to extract
topological anomaly signals that are invisible to standard density estimators.

Theory
------
Authentication events are projected into a high-dimensional feature space.
A Vietoris-Rips filtration is constructed over this point cloud using a
**Gower mixed distance metric** (handles both continuous and categorical
features). As the filtration parameter ε grows, topological features
(connected components, loops) are born and die.

- **Betti-0** (β₀): Number of connected components.
  Security meaning: isolated clusters = distributed brute-force attempts
  from distinct origins that share no behavioral similarity.

- **Betti-1** (β₁): Number of 1-dimensional holes / loops.
  Security meaning: cyclical paths = lateral movement patterns that
  form closed circuits in the credential graph (attempting to return
  to earlier access points to avoid straight-line forensics).

Features with **long persistence** (born early, die late) are structural
signals. Short-lived features are dismissed as noise.

The topological anomaly score is the Mahalanobis distance of a new event's
persistence summary from the training distribution of persistence diagrams.

Reference
---------
- Hajij et al. (2022): "Topological Data Analysis for Anomaly Detection in
  Host-Based Logs." arXiv:2204.12919
- Edelsbrunner & Harer (2010): Computational Topology.

Dependencies
------------
    pip install gudhi scikit-tda scipy scikit-learn

This module degrades gracefully if these are not installed.

Usage
-----
    from chimera.experimental.topology import TopologyAnalyzer, HAS_TDA

    if not HAS_TDA:
        logger.warning("TDA dependencies not installed. Topology disabled.")
    else:
        tda = TopologyAnalyzer(epsilon=0.5, max_dimension=1)
        tda.fit(X_train_df)
        scores = tda.topological_anomaly_score(X_test_df)
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Feature flag: TDA is only available if gudhi is installed
try:
    import gudhi  # noqa: F401
    from gudhi import RipsComplex
    HAS_TDA = True
    logger.debug("[topology] gudhi available — TDA enabled.")
except ImportError:
    HAS_TDA = False
    logger.warning(
        "[topology] gudhi not found. TDA features are disabled. "
        "Install with: pip install gudhi"
    )


def _require_tda() -> None:
    if not HAS_TDA:
        raise ImportError(
            "TDA requires gudhi. Install with: pip install gudhi\n"
            "TopologyAnalyzer cannot be used without this dependency."
        )


# ------------------------------------------------------------------
# Gower distance
# ------------------------------------------------------------------

def gower_distance_matrix(
    X: "np.ndarray",
    categorical_cols: Optional[list[int]] = None,
) -> np.ndarray:
    """Compute pairwise Gower distance matrix for mixed-type data.

    Gower distance normalizes continuous features by their range and uses
    binary (0/1) distance for categorical features. The result is always
    in [0, 1].

    Parameters
    ----------
    X:
        2-D array of shape (n_samples, n_features). Categorical columns
        should be integer-encoded.
    categorical_cols:
        Indices of columns that are categorical. All other columns are
        treated as continuous.

    Returns
    -------
    np.ndarray
        Symmetric distance matrix of shape (n, n), values in [0, 1].
    """
    n, d = X.shape
    cat_set = set(categorical_cols or [])
    dist = np.zeros((n, n), dtype=np.float64)

    # Precompute column ranges for continuous normalization
    col_ranges = np.ones(d, dtype=np.float64)
    for j in range(d):
        if j not in cat_set:
            col_min, col_max = X[:, j].min(), X[:, j].max()
            col_ranges[j] = max(col_max - col_min, 1e-9)

    for i in range(n):
        for j in range(i + 1, n):
            partial = 0.0
            for k in range(d):
                if k in cat_set:
                    partial += float(X[i, k] != X[j, k])
                else:
                    partial += abs(X[i, k] - X[j, k]) / col_ranges[k]
            g = partial / d
            dist[i, j] = g
            dist[j, i] = g

    return dist


# ------------------------------------------------------------------
# TopologyAnalyzer
# ------------------------------------------------------------------

class TopologyAnalyzer:
    """Vietoris-Rips persistent homology on behavioral feature vectors.

    **Experimental — requires gudhi.**

    Parameters
    ----------
    epsilon:
        Maximum filtration parameter (radius). Controls the scale at which
        topological features are considered. Should be tuned based on the
        expected spread of your feature space (typically 0.3–0.8 for
        normalized Gower distances).
    max_dimension:
        Maximum homology dimension to compute.
        - 0: connected components (β₀) only. Fast.
        - 1: connected components + loops (β₀ + β₁). Recommended.
        - 2+: 2-simplices and higher. Very expensive; not recommended.
    max_samples:
        Maximum number of samples to use for TDA (subsampled for efficiency).
        Vietoris-Rips has O(n²) memory; default 2000 is safe for most machines.
    categorical_cols:
        Column indices to treat as categorical in Gower distance.
    """

    def __init__(
        self,
        epsilon: float = 0.5,
        max_dimension: int = 1,
        max_samples: int = 2000,
        categorical_cols: Optional[list[int]] = None,
    ) -> None:
        _require_tda()
        self.epsilon = epsilon
        self.max_dimension = max_dimension
        self.max_samples = max_samples
        self.categorical_cols = categorical_cols or []
        self._persistence: Optional[list] = None
        self._train_diagrams: Optional[np.ndarray] = None
        self._mahal_mean: Optional[np.ndarray] = None
        self._mahal_cov_inv: Optional[np.ndarray] = None

    # ------------------------------------------------------------------
    # Fitting
    # ------------------------------------------------------------------

    def fit(self, X: np.ndarray, seed: int = 42) -> "TopologyAnalyzer":
        """Build Vietoris-Rips complex on training data.

        Parameters
        ----------
        X:
            Training feature matrix (n_samples, n_features). Values should
            be numeric; categorical columns are identified via ``categorical_cols``.
        seed:
            Random seed for subsampling (determinism).

        Returns
        -------
        TopologyAnalyzer
            Self.
        """
        X = np.asarray(X, dtype=np.float64)
        n = X.shape[0]

        if n > self.max_samples:
            rng = np.random.default_rng(seed)
            idx = rng.choice(n, size=self.max_samples, replace=False)
            X_sample = X[idx]
            logger.info(
                "[topology] Subsampled %d → %d events for TDA.", n, self.max_samples
            )
        else:
            X_sample = X

        logger.info(
            "[topology] Computing Gower distance matrix (%d × %d)…",
            len(X_sample), len(X_sample),
        )
        dist_matrix = gower_distance_matrix(X_sample, self.categorical_cols)

        logger.info("[topology] Building Vietoris-Rips complex (epsilon=%.3f)…", self.epsilon)
        rips = RipsComplex(distance_matrix=dist_matrix, max_edge_length=self.epsilon)
        simplex_tree = rips.create_simplex_tree(max_dimension=self.max_dimension + 1)
        simplex_tree.compute_persistence()

        self._persistence = simplex_tree.persistence()

        # Encode persistence diagrams as feature vectors for Mahalanobis scoring
        self._train_diagrams = self._encode_persistence(self._persistence)
        if self._train_diagrams is not None and len(self._train_diagrams) > 2:
            self._fit_mahalanobis(self._train_diagrams)

        logger.info(
            "[topology] Fit complete. Betti-0=%d, Betti-1=%d intervals.",
            self._betti_count(0), self._betti_count(1),
        )
        return self

    # ------------------------------------------------------------------
    # Persistence barcode
    # ------------------------------------------------------------------

    def persistence_barcodes(self) -> dict[int, list[tuple[float, float]]]:
        """Return persistence barcodes grouped by dimension.

        Returns
        -------
        dict[int, list[tuple[float, float]]]
            ``{dimension: [(birth, death), ...]}``
            Infinite death values (topology that never disappears) are
            represented as ``float('inf')``.
        """
        if self._persistence is None:
            raise RuntimeError("Call fit() first.")

        barcodes: dict[int, list[tuple[float, float]]] = {}
        for dim, (birth, death) in self._persistence:
            barcodes.setdefault(dim, []).append((birth, death))
        return barcodes

    def betti_numbers(self) -> dict[int, int]:
        """Return Betti numbers β₀ and β₁ at epsilon.

        Betti number = count of features that are alive at the maximum
        filtration scale (epsilon).
        """
        if self._persistence is None:
            raise RuntimeError("Call fit() first.")

        betti: dict[int, int] = {}
        for dim in range(self.max_dimension + 1):
            count = sum(
                1
                for d, (birth, death) in self._persistence
                if d == dim and birth <= self.epsilon
                and (death == float("inf") or death >= self.epsilon)
            )
            betti[dim] = count
        return betti

    # ------------------------------------------------------------------
    # Topological anomaly score
    # ------------------------------------------------------------------

    def topological_anomaly_score(
        self,
        X: np.ndarray,
        seed: int = 42,
    ) -> np.ndarray:
        """Compute topological anomaly scores for new events.

        Uses Mahalanobis distance from the persistence diagram distribution
        fitted on the training set. Events whose persistence signatures are
        far from the training distribution receive high scores.

        Parameters
        ----------
        X:
            Test feature matrix (n_samples, n_features).

        Returns
        -------
        np.ndarray
            1-D anomaly score array. Higher = more topologically anomalous.
        """
        _require_tda()
        if self._train_diagrams is None or self._mahal_mean is None:
            raise RuntimeError("Call fit() before topological_anomaly_score().")

        X = np.asarray(X, dtype=np.float64)
        n = X.shape[0]

        # Compute persistence for test data in chunks
        if n > self.max_samples:
            rng = np.random.default_rng(seed)
            idx = rng.choice(n, size=self.max_samples, replace=False)
            X_eval = X[idx]
        else:
            X_eval = X
            idx = np.arange(n)

        dist_matrix = gower_distance_matrix(X_eval, self.categorical_cols)
        rips = RipsComplex(distance_matrix=dist_matrix, max_edge_length=self.epsilon)
        simplex_tree = rips.create_simplex_tree(max_dimension=self.max_dimension + 1)
        simplex_tree.compute_persistence()
        test_persistence = simplex_tree.persistence()

        # Encode and score
        test_vec = self._encode_persistence(test_persistence)
        if test_vec is None or self._mahal_cov_inv is None:
            # Fallback: zero scores
            return np.zeros(n, dtype=np.float64)

        # Broadcast: all events in the chunk get the same topology score
        # (TDA is computed on the collective point cloud, not per-event)
        chunk_score = float(self._mahalanobis(test_vec, self._mahal_mean, self._mahal_cov_inv))
        scores = np.zeros(n, dtype=np.float64)
        scores[idx] = chunk_score
        return scores

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _betti_count(self, dim: int) -> int:
        if self._persistence is None:
            return 0
        return sum(1 for d, _ in self._persistence if d == dim)

    def _encode_persistence(self, persistence: list) -> Optional[np.ndarray]:
        """Encode persistence diagram as a fixed-length feature vector.

        Uses a simple encoding: for each dimension, compute total persistence
        (sum of lifetimes), max persistence, and count of features.
        Infinite lifetimes are replaced by epsilon (upper bound).
        """
        if not persistence:
            return None

        features = []
        for dim in range(self.max_dimension + 1):
            intervals = [
                (b, d if d != float("inf") else self.epsilon)
                for d_val, (b, d) in persistence
                if d_val == dim
            ]
            if not intervals:
                features.extend([0.0, 0.0, 0.0])
                continue
            lifetimes = [max(0.0, death - birth) for birth, death in intervals]
            features.append(float(np.sum(lifetimes)))
            features.append(float(np.max(lifetimes)))
            features.append(float(len(lifetimes)))

        return np.array(features, dtype=np.float64)

    def _fit_mahalanobis(self, vecs: np.ndarray) -> None:
        """Fit the Mahalanobis distance parameters on training encodings."""
        if vecs.ndim == 1:
            vecs = vecs.reshape(1, -1)
        self._mahal_mean = vecs.mean(axis=0)
        cov = np.cov(vecs.T) if vecs.shape[0] > 1 else np.eye(vecs.shape[1])
        # Regularize to ensure invertible
        cov += np.eye(cov.shape[0]) * 1e-6
        try:
            self._mahal_cov_inv = np.linalg.inv(cov)
        except np.linalg.LinAlgError:
            logger.warning("[topology] Covariance matrix singular; using identity.")
            self._mahal_cov_inv = np.eye(cov.shape[0])

    @staticmethod
    def _mahalanobis(x: np.ndarray, mean: np.ndarray, cov_inv: np.ndarray) -> float:
        diff = x - mean
        return float(np.sqrt(max(0.0, diff @ cov_inv @ diff)))

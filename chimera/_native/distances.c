/*
 * chimera/_native/distances.c
 *
 * Fast pairwise Euclidean distance computation using the BLAS Gram matrix trick.
 *
 * The key identity:
 *
 *   dist²(i, j) = ||x_i - x_j||²
 *              = ||x_i||² + ||x_j||² - 2·(x_i · x_j)
 *              = norms[i] + norms[j] - 2·G[i,j]
 *
 * where G = X @ X.T is computed in a single BLAS DGEMM call.
 *
 * This is the same approach used internally by FAISS and sklearn's
 * euclidean_distances(), but exposed directly to eliminate Python-level
 * overhead when calling from chimera/detectors/lof.py.
 *
 * Build:
 *   python _native/build.py        (sets USE_CBLAS automatically)
 *   Fallback: naive O(n²d) triple loop when CBLAS is unavailable.
 *
 * Memory: O(n²) for the Gram matrix. Maximum safe n for 8 GB RAM ≈ 32,000.
 * Use max_samples in the config to stay within your memory budget.
 *
 * Exposed symbol (called via ctypes from lof.py):
 *   void euclidean_distances(
 *       const double *X,   // row-major (n, d)
 *       int n,
 *       int d,
 *       double *out        // row-major (n, n), caller allocates
 *   )
 */
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef USE_CBLAS
  #include <cblas.h>
#endif

/* ---------------------------------------------------------------
 * Compute squared L2 norms for each row of X (n, d) → norms (n,)
 * --------------------------------------------------------------- */
static void row_norms_sq(const double *X, int n, int d, double *norms) {
    for (int i = 0; i < n; i++) {
        double s = 0.0;
        const double *row = X + (size_t)i * d;
        for (int j = 0; j < d; j++) {
            double v = row[j];
            s += v * v;
        }
        norms[i] = s;
    }
}

/* ---------------------------------------------------------------
 * euclidean_distances
 *
 * Fills out[i*n + j] = Euclidean distance between rows i and j of X.
 * Diagonal = 0. Negative values clamped to 0 before sqrt (numerical noise).
 * --------------------------------------------------------------- */
void euclidean_distances(const double *X, int n, int d, double *out) {
    if (!X || !out || n <= 0 || d <= 0) return;

    double *gram  = (double *)malloc((size_t)n * n * sizeof(double));
    double *norms = (double *)malloc((size_t)n * sizeof(double));

    if (!gram || !norms) {
        /* Allocation failure: fill output with zeros and return */
        if (gram)  free(gram);
        if (norms) free(norms);
        memset(out, 0, (size_t)n * n * sizeof(double));
        return;
    }

    row_norms_sq(X, n, d, norms);

#ifdef USE_CBLAS
    /*
     * BLAS DGEMM: G = X @ X.T
     * C = alpha * A @ B + beta * C
     * A = X (n×d), B = X^T (d×n) → C = G (n×n)
     */
    cblas_dgemm(
        CblasRowMajor,
        CblasNoTrans, CblasTrans,
        n, n, d,
        1.0, X, d, X, d,
        0.0, gram, n
    );
#else
    /* Fallback: naive Gram matrix computation */
    for (int i = 0; i < n; i++) {
        for (int j = i; j < n; j++) {
            double dot = 0.0;
            const double *ri = X + (size_t)i * d;
            const double *rj = X + (size_t)j * d;
            for (int k = 0; k < d; k++) dot += ri[k] * rj[k];
            gram[i * n + j] = dot;
            gram[j * n + i] = dot;
        }
    }
#endif

    /* dist²(i,j) = norms[i] + norms[j] - 2·G[i,j], clamped ≥ 0 */
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            double d2 = norms[i] + norms[j] - 2.0 * gram[(size_t)i * n + j];
            out[(size_t)i * n + j] = (d2 > 0.0) ? sqrt(d2) : 0.0;
        }
    }

    free(gram);
    free(norms);
}

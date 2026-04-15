"""
chimera/_native/distances.h

Header for the fast Euclidean distance extension.
"""
#ifndef CHIMERA_DISTANCES_H
#define CHIMERA_DISTANCES_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * euclidean_distances(X, n, d, out)
 *
 * Compute the n×n pairwise Euclidean distance matrix for an n×d
 * row-major matrix X. Result is written to out (caller allocates n*n doubles).
 */
void euclidean_distances(const double *X, int n, int d, double *out);

#ifdef __cplusplus
}
#endif

#endif /* CHIMERA_DISTANCES_H */

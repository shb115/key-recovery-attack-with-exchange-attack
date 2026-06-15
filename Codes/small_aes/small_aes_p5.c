/*
 * small_aes_p5.c
 *
 * Direct measurement of the one-round exchange probability P_5(1,k) on
 * Small-AES (4-bit cells, 4x4 state).  This verifies the probability
 * formula
 *     P_5(i,k) = sum_{j=1}^{3} C(4,j) * (2^-c)^{4(i+j) - 2ij - jk}
 * (c = cell bit width = 4 for Small-AES) used in both the 5-round
 * (k=2) and 6-round (k=1) exchange distinguishers.
 *
 * Unlike the end-to-end distinguisher, this experiment checks the exact
 * algebraic one-round condition (Eq. (1) of the paper):
 *     (R(a'), R(b')) = (rho_d^{v'}(R(a), R(b)), rho_d^{v'}(R(b), R(a)))
 * for some v' in F_2^4.  Because this is an exact structural condition
 * (not a zero-difference pattern that can also occur at random), there is
 * no random collision floor, so P_5 can be measured cleanly at a feasible
 * sample size.  This is the one probabilistic ingredient of the 6-round
 * complexity that is not pure combinatorics; the equivalence-class
 * formation is a round-independent structural property (Theorem) and the
 * one-round propagations are combinatorial zero-byte counts.
 *
 * Setup for P_5(1,k):
 *   - a, b agree on k inactive diagonals and differ on (4-k) active ones.
 *   - a' = rho_d^{(1,0,0,0)}(a,b), b' = rho_d^{(1,0,0,0)}(b,a)
 *     (exchange the active diagonal 0).
 *   - apply one round R = AK; SubNibbles; ShiftRows; MixColumns.
 *   - check whether (R(a'), R(b')) is a diagonal exchange of (R(a), R(b)).
 *
 * Expected values (Small-AES, c=4):
 *   P_5(1,1) = 4*2^-20 + 6*2^-24 + 4*2^-28 ~= 2^-17.87   (6-round trail)
 *   P_5(1,2) = 14*2^-16                    ~= 2^-12.19   (5-round trail)
 *
 * Usage:
 *   ./small_aes_p5 [k] [trials]
 *   Defaults: k=1, trials=268435456 (2^28). The RNG is seeded from the system
 *   clock (no seed argument); runs started at different times draw independent
 *   samples.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* Small-AES encryption T-tables (SubNibbles+ShiftRows+MixColumns),
 * identical to small_aes.c used elsewhere in this artifact. The S-box is
 * already fused into the T-tables, so it is not needed separately here. */
static const uint16_t T0[16] = {
    0xC66A, 0x5BBE, 0xA55F, 0x844C, 0x4226, 0xFEE1, 0xE779, 0x7AAD,
    0x1998, 0x9DD4, 0xDFF2, 0xBCC7, 0x6335, 0x2113, 0x0000, 0x388B
};
static const uint16_t T1[16] = {
    0xAC66, 0xE5BB, 0xFA55, 0xC844, 0x6422, 0x1FEE, 0x9E77, 0xD7AA,
    0x8199, 0x49DD, 0x2DFF, 0x7BCC, 0x5633, 0x3211, 0x0000, 0xB388
};
static const uint16_t T2[16] = {
    0x6AC6, 0xBE5B, 0x5FA5, 0x4C84, 0x2642, 0xE1FE, 0x79E7, 0xAD7A,
    0x9819, 0xD49D, 0xF2DF, 0xC7BC, 0x3563, 0x1321, 0x0000, 0x8B38
};
static const uint16_t T3[16] = {
    0x66AC, 0xBBE5, 0x55FA, 0x44C8, 0x2264, 0xEE1F, 0x779E, 0xAAD7,
    0x9981, 0xDD49, 0xFF2D, 0xCC7B, 0x3356, 0x1132, 0x0000, 0x88B3
};

/* One AES round on a 4x4 nibble state: AddRoundKey, then SB+SR+MC via the
 * T-tables.  state[row][col]; diagonal d occupies cells (r, (r+d) mod 4). */
static void one_round(uint8_t out[4][4], const uint8_t in[4][4],
                      const uint8_t key[4][4]) {
    uint8_t s[4][4];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            s[i][j] = in[i][j] ^ key[i][j];
    uint16_t c[4];
    c[0] = T0[s[0][0]] ^ T1[s[1][1]] ^ T2[s[2][2]] ^ T3[s[3][3]];
    c[1] = T0[s[0][1]] ^ T1[s[1][2]] ^ T2[s[2][3]] ^ T3[s[3][0]];
    c[2] = T0[s[0][2]] ^ T1[s[1][3]] ^ T2[s[2][0]] ^ T3[s[3][1]];
    c[3] = T0[s[0][3]] ^ T1[s[1][0]] ^ T2[s[2][1]] ^ T3[s[3][2]];
    for (int j = 0; j < 4; j++) {
        out[0][j] = (c[j] >> 12) & 0xF;
        out[1][j] = (c[j] >>  8) & 0xF;
        out[2][j] = (c[j] >>  4) & 0xF;
        out[3][j] =  c[j]        & 0xF;
    }
}

/* Is diagonal d of X equal to diagonal d of Y? */
static inline int diag_equal(const uint8_t X[4][4], const uint8_t Y[4][4],
                             int d) {
    for (int r = 0; r < 4; r++)
        if (X[r][(r + d) & 3] != Y[r][(r + d) & 3]) return 0;
    return 1;
}

/* 64-bit xorshift, long period to avoid RNG cycling over many trials. */
static inline uint64_t xorshift64(uint64_t *st) {
    uint64_t x = *st;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *st = x;
    return x;
}

/* Nibble reservoir: 16 nibbles per 64-bit draw. */
typedef struct { uint64_t pool; int cnt; uint64_t st; } NibSrc;
static inline uint8_t nib(NibSrc *n) {
    if (n->cnt == 0) { n->pool = xorshift64(&n->st); n->cnt = 16; }
    uint8_t v = n->pool & 0xF;
    n->pool >>= 4;
    n->cnt--;
    return v;
}

int main(int argc, char **argv) {
    int k = 1;
    uint64_t trials = 1ULL << 28;
    if (argc > 1) k = atoi(argv[1]);
    if (argc > 2) trials = strtoull(argv[2], NULL, 10);
    if (k < 1 || k > 3) { fprintf(stderr, "k must be 1..3\n"); return 1; }

    int num_active = 4 - k;            /* active diagonals: 0 .. num_active-1 */
    if (num_active < 1) { fprintf(stderr, "need >=1 active diagonal\n"); return 1; }

    /* Expected P_5(1,k) = sum_{j=1}^3 C(4,j) (2^-4)^{4(1+j)-2j-jk}. */
    static const int binom[4] = {1, 4, 6, 4};
    double expected = 0.0, exp_j[4] = {0,0,0,0};
    for (int j = 1; j <= 3; j++) {
        int e = 4 * (1 + j) - 2 * j - j * k;   /* exponent in cells */
        exp_j[j] = (double)binom[j] * pow(2.0, -4.0 * e);
        expected += exp_j[j];
    }

    printf("==============================================================\n");
    printf("[*] Direct one-round measurement of P_5(1,%d)  (Small-AES, c=4)\n", k);
    printf("    Active diagonals : %d   Inactive (k) : %d\n", num_active, k);
    printf("    Trials           : %llu (2^%.2f)\n",
           (unsigned long long)trials, log2((double)trials));
    printf("    Expected P_5(1,%d) = %.6e  (2^%.4f)\n",
           k, expected, log2(expected));
    for (int j = 1; j <= 3; j++)
        printf("        j=%d term : %.6e  (C(4,%d)=%d, fraction %.4f)\n",
               j, exp_j[j], j, binom[j], exp_j[j] / expected);
    printf("==============================================================\n\n");
    fflush(stdout);

    /* The key is refreshed periodically so the estimate averages over keys
     * as well as plaintexts (reduces run-to-run variance). The RNG is seeded
     * from the system clock, matching the full-AES code. */
    NibSrc ns; ns.pool = 0; ns.cnt = 0;
    ns.st = ((uint64_t)time(NULL) ^ 0x9E3779B97F4A7C15ULL) | 1ULL;
    uint8_t K[4][4];
    for (int r = 0; r < 4; r++) for (int col = 0; col < 4; col++) K[r][col] = nib(&ns);

    uint64_t success = 0;              /* trials with >=1 valid mask (P[exists]) */
    uint64_t mask_total = 0;           /* total valid weight-1..3 masks (E[count]) */
    uint64_t mask_w[4] = {0,0,0,0};    /* valid masks per weight j=1,2,3 */

    for (uint64_t t = 0; t < trials; t++) {
        uint8_t A[4][4], B[4][4], Ap[4][4], Bp[4][4];

        /* refresh the key every 2^16 trials */
        if ((t & 0xFFFFULL) == 0)
            for (int r = 0; r < 4; r++)
                for (int col = 0; col < 4; col++) K[r][col] = nib(&ns);

        for (int d = 0; d < 4; d++) {
            if (d < num_active) {
                /* active diagonal: independent random values for A and B */
                for (int r = 0; r < 4; r++) {
                    A[r][(r + d) & 3] = nib(&ns);
                    B[r][(r + d) & 3] = nib(&ns);
                }
            } else {
                /* inactive diagonal: identical in A and B */
                for (int r = 0; r < 4; r++) {
                    uint8_t v = nib(&ns);
                    A[r][(r + d) & 3] = v;
                    B[r][(r + d) & 3] = v;
                }
            }
        }

        /* a' = rho_d^{(1,0,0,0)}(a,b), b' = rho_d^{(1,0,0,0)}(b,a):
         * swap diagonal 0 (cells (r,r)). */
        memcpy(Ap, A, 16);
        memcpy(Bp, B, 16);
        for (int r = 0; r < 4; r++) {
            Ap[r][r] = B[r][r];
            Bp[r][r] = A[r][r];
        }

        uint8_t RA[4][4], RB[4][4], RAp[4][4], RBp[4][4];
        one_round(RA,  A,  K);
        one_round(RB,  B,  K);
        one_round(RAp, Ap, K);
        one_round(RBp, Bp, K);

        /* Eq.(1): (R(a'),R(b')) must be a diagonal exchange of (R(a),R(b))
         * for some mask v'.  Precompute, per diagonal, whether keeping or
         * swapping is consistent, then test every weight-1..3 mask exactly.
         * Two quantities are recorded:
         *   - mask_total / trials  = E[# valid masks], which equals the
         *     formula sum_j C(4,j) P(1,j,k) by linearity of expectation;
         *   - success / trials     = P[at least one valid mask], the
         *     operational trail probability (<= formula, due to overlaps).
         * Weight 4 (full swap, the degenerate a'=b) is excluded, matching
         * the paper's sum over j in {1,2,3}. */
        int keep_ok[4], swap_ok[4];
        for (int d = 0; d < 4; d++) {
            keep_ok[d] = diag_equal(RAp, RA, d) && diag_equal(RBp, RB, d);
            swap_ok[d] = diag_equal(RAp, RB, d) && diag_equal(RBp, RA, d);
        }
        int cnt = 0;
        for (int v = 1; v <= 14; v++) {        /* masks of weight 1..3 */
            int w = __builtin_popcount(v);
            if (w < 1 || w > 3) continue;
            int valid = 1;
            for (int d = 0; d < 4; d++) {
                int want_swap = (v >> d) & 1;
                if (want_swap ? !swap_ok[d] : !keep_ok[d]) { valid = 0; break; }
            }
            if (valid) { cnt++; mask_w[w]++; }
        }
        mask_total += (uint64_t)cnt;
        if (cnt > 0) success++;

        if (((t + 1) & ((1ULL << 26) - 1)) == 0) {
            fprintf(stderr, "\r[Progress] %llu/%llu  successes=%llu   ",
                    (unsigned long long)(t + 1), (unsigned long long)trials,
                    (unsigned long long)success);
            fflush(stderr);
        }
    }
    fprintf(stderr, "\n");

    double e_count = (double)mask_total / (double)trials;   /* E[# masks]  */
    double p_exist = (double)success    / (double)trials;   /* P[exists]   */

    printf("--- Result ---\n");
    printf("Trials                       : %llu\n", (unsigned long long)trials);
    printf("\n[1] E[# valid masks] (matches the formula by linearity)\n");
    printf("    observed  : %.6e  (2^%.4f)\n",
           e_count, (e_count > 0 ? log2(e_count) : -999.0));
    printf("    formula   : %.6e  (2^%.4f)  = sum_j C(4,j) P(1,j,%d)\n",
           expected, log2(expected), k);
    printf("    ratio     : %.4f\n", (expected > 0 ? e_count / expected : 0.0));
    {
        /* variance of the per-trial mask count is unknown a priori; report
         * a Poisson-like error bar on the total count as a rough guide. */
        double se = (mask_total > 0)
            ? sqrt((double)mask_total) / (double)trials : 0.0;
        printf("    approx. error : %.2f%%\n",
               e_count > 0 ? 100.0 * se / e_count : 0.0);
    }
    printf("\n    per-weight (E[# weight-j masks] = C(4,j) P(1,j,%d)):\n", k);
    for (int j = 1; j <= 3; j++) {
        double obsj = (double)mask_w[j] / (double)trials;
        printf("      j=%d : observed %.6e (2^%.4f)   formula %.6e (2^%.4f)   ratio %.4f\n",
               j, obsj, (obsj > 0 ? log2(obsj) : -999.0),
               exp_j[j], log2(exp_j[j]),
               exp_j[j] > 0 ? obsj / exp_j[j] : 0.0);
    }
    printf("\n[2] P[at least one valid mask] (operational trail probability)\n");
    printf("    observed  : %.6e  (2^%.4f)\n",
           p_exist, (p_exist > 0 ? log2(p_exist) : -999.0));
    printf("    note: <= formula because the formula is a union-bound sum;\n");
    printf("          the gap is the overlap between distinct exchange masks.\n");
    return 0;
}

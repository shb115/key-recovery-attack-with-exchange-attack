/*
 * exchange_keyrecovery_6r_filter.c -- verification of the key filtering of the
 * 6-round attack (Algorithm 4) with synthetic right classes.
 *
 * The 6-round distinguisher itself (2^89 data) cannot be run, but the key
 * filtering only needs the two detected pairs of a right class.  Such a pair is
 * represented here by a pair (alpha, beta) with three active diagonals
 * (e, o1, o2) = (0, 1, 2) that satisfies the one-round exchange condition for
 * the exchange of diagonal e.  Under the correct k0 this means (Observation 2):
 * for some J with {} != J != {0,1,2,3},
 *     Delta[(e-d) mod 4, e] = 0 for all d not in J,
 *     Delta[(o-d) mod 4, o] = 0 for all d in J, o in {o1, o2},
 * where Delta = R(alpha) ^ R(beta) (difference after the first MC).
 *
 * For each trial: draw a random k0, sample right classes by rejection
 * (random diagonal values, keep the pairs satisfying the condition under k0), then
 *  (a) check that the correct key satisfies the condition of every right class;
 *  (b) measure the probability that a random wrong guess of the three active
 *      diagonals (96 bits) satisfies the condition of one right class
 *      -- expected P*_5(1,1) = 2^-38, measured per-column and combined;
 *  (c) find, with the MITM tables, all guesses of the three active diagonals
 *      that satisfy the conditions of TWO right classes (any J1, J2), and count
 *      them -- expected about 2^96 * (2^-38)^2 = 2^20 random survivors plus the
 *      "partially correct" guesses, and verify the correct key is among them.
 *
 * Usage: key_recovery_6r_filter trials seed threads
 * Output (CSV per trial):
 *   trial,seed,correct_ok,log2_p_wrong_pair0,log2_p_wrong_pair1,log2_p_wrong_geomean,
 *   log2_cand_two_pairs,true_in_cand,secs
 *   (p_wrong = probability that a random 96-bit guess is consistent with the
 *   given right class, expected 2^-38; cand = number of 96-bit guesses
 *   satisfying both right classes, expected about 2^20 plus partially
 *   correct guesses.)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <immintrin.h>
#include <omp.h>

static uint8_t SBOX[256];
static uint32_t TE[4][256];
static void init_tables(void) {
    for (int v = 0; v < 256; v++) {
        __m128i s = _mm_aesenclast_si128(_mm_set1_epi8((char)v), _mm_setzero_si128());
        SBOX[v] = (uint8_t)_mm_extract_epi8(s, 0);
    }
    static const int MCm[4][4] = {{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};
    for (int r = 0; r < 4; r++)
        for (int x = 0; x < 256; x++) {
            uint8_t s = SBOX[x], s2 = (uint8_t)((s << 1) ^ ((s & 0x80) ? 0x1B : 0)), s3 = s2 ^ s;
            uint32_t w = 0;
            for (int k = 0; k < 4; k++) { int c = MCm[k][r]; w |= (uint32_t)(c == 1 ? s : (c == 2 ? s2 : s3)) << (8 * k); }
            TE[r][x] = w;
        }
}
static inline uint32_t colimg(uint32_t a) {
    return TE[0][a & 0xFF] ^ TE[1][(a >> 8) & 0xFF] ^ TE[2][(a >> 16) & 0xFF] ^ TE[3][a >> 24];
}
static inline int zmask32(uint32_t v) {
    uint32_t t = (v & 0x7F7F7F7Fu) + 0x7F7F7F7Fu; t = ~(t | v | 0x7F7F7F7Fu);
    return (int)(((t >> 7) & 1) | ((t >> 14) & 2) | ((t >> 21) & 4) | ((t >> 28) & 8));
}
static uint64_t sm_s;
static inline uint64_t sm64(void) {
    uint64_t z = (sm_s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL; z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL; return z ^ (z >> 31);
}

/* row masks required in column e and in columns o1,o2 for exchange set J (bit d of J = diagonal d) */
static int NEED_E[16], NEED_O[16];
static void init_need(void) {
    const int e = 0, o1 = 1;   /* o2 = 2: same row rule as o1 with o=2 */
    (void)o1;
    for (int J = 0; J < 16; J++) {
        int ne = 0, no1 = 0, no2 = 0;
        for (int d = 0; d < 4; d++) {
            if (!((J >> d) & 1)) ne |= 1 << ((e - d) & 3);
            else { no1 |= 1 << ((1 - d) & 3); no2 |= 1 << ((2 - d) & 3); }
        }
        NEED_E[J] = ne; NEED_O[J] = no1 | (no2 << 4);   /* pack o1 rows (low nibble) and o2 rows (high nibble) */
    }
}
/* is the triple of zero masks (ze, z1, z2) consistent with some J? */
static inline int consistent(int ze, int z1, int z2) {
    for (int J = 1; J <= 14; J++)
        if ((ze & NEED_E[J]) == NEED_E[J] && (z1 & (NEED_O[J] & 15)) == (NEED_O[J] & 15) && (z2 & (NEED_O[J] >> 4)) == (NEED_O[J] >> 4)) return 1;
    return 0;
}

typedef struct { uint32_t x[3], y[3]; } rcp_t;   /* diagonal values (e,o1,o2) of the two plaintexts */

/* guesses of one 32-bit diagonal whose column zero-mask, for the two right classes c1,c2, is (m1,m2): count via full scan (2^32 with tables, threaded) */
static uint64_t scan_col_pairs(const rcp_t *a, const rcp_t *b, int col, uint64_t hist[256], uint32_t truekey, int *true_bucket) {
    /* hist[m1*16+m2] = number of guesses g with zmask(colimg(x^g)^colimg(x'^g)) = m1 for a, = m2 for b */
    uint32_t DTa[4][256], DTb[4][256];
    for (int r = 0; r < 4; r++)
        for (int x = 0; x < 256; x++) {
            DTa[r][x] = TE[r][((a->x[col] >> (8 * r)) & 0xFF) ^ x] ^ TE[r][((a->y[col] >> (8 * r)) & 0xFF) ^ x];
            DTb[r][x] = TE[r][((b->x[col] >> (8 * r)) & 0xFF) ^ x] ^ TE[r][((b->y[col] >> (8 * r)) & 0xFF) ^ x];
        }
    memset(hist, 0, 256 * sizeof(uint64_t));
    int T = omp_get_max_threads();
    uint64_t (*lh)[256] = calloc(T, sizeof(uint64_t[256]));
    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        #pragma omp for schedule(dynamic, 1024)
        for (uint32_t hi = 0; hi < (1u << 24); hi++) {
            uint32_t g1 = hi & 0xFF, g2 = (hi >> 8) & 0xFF, g3 = hi >> 16;
            uint32_t pa = DTa[1][g1] ^ DTa[2][g2] ^ DTa[3][g3], pb = DTb[1][g1] ^ DTb[2][g2] ^ DTb[3][g3];
            for (uint32_t g0 = 0; g0 < 256; g0++)
                lh[tid][zmask32(pa ^ DTa[0][g0]) * 16 + zmask32(pb ^ DTb[0][g0])]++;
        }
    }
    for (int t = 0; t < T; t++) for (int k = 0; k < 256; k++) hist[k] += lh[t][k];
    free(lh);
    uint32_t g = truekey;
    int ma = zmask32(colimg(a->x[col] ^ g) ^ colimg(a->y[col] ^ g)), mb = zmask32(colimg(b->x[col] ^ g) ^ colimg(b->y[col] ^ g));
    *true_bucket = ma * 16 + mb;
    uint64_t tot = 0; for (int k = 0; k < 256; k++) tot += hist[k];
    return tot;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: key_recovery_6r_filter trials seed threads\n"); return 1; }
    long trials = atol(argv[1]); uint64_t seed = strtoull(argv[2], NULL, 10); omp_set_num_threads(atoi(argv[3]));
    init_tables(); init_need();
    for (long t = 0; t < trials; t++) {
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        sm_s = seed * 0x100000001B3ULL ^ (uint64_t)t * 0xD6E8FEB86659FD93ULL; sm64(); sm64();
        uint32_t k[3]; for (int c = 0; c < 3; c++) k[c] = (uint32_t)sm64();
        /* sample two right classes by rejection: about 2^38 draws each is too many, so
           sample column e first (its zero rows fix J), then draw o-columns until they match */
        rcp_t rc[2];
        for (int i = 0; i < 2; i++) {
            for (;;) {
                uint32_t xe = (uint32_t)sm64(), ye = (uint32_t)sm64();
                int ze = zmask32(colimg(xe ^ k[0]) ^ colimg(ye ^ k[0]));
                if (!ze || ze == 15) continue;                       /* need 1..3 zero rows in column e */
                /* pick J = complement of ze over diagonals (rows of e map d -> row (e-d)&3 = (-d)&3) */
                int J = 0; for (int d = 0; d < 4; d++) if (!((ze >> ((0 - d) & 3)) & 1)) J |= 1 << d;
                if (J == 0 || J == 15) continue;
                /* draw o1,o2 values until required rows are zero (prob 2^-8|J| each) */
                uint32_t xo[2], yo[2]; int okc = 1;
                for (int c = 0; c < 2 && okc; c++) {
                    int need = c == 0 ? (NEED_O[J] & 15) : (NEED_O[J] >> 4); long tries = 0;
                    for (;;) {
                        xo[c] = (uint32_t)sm64(); yo[c] = (uint32_t)sm64();
                        int z = zmask32(colimg(xo[c] ^ k[c + 1]) ^ colimg(yo[c] ^ k[c + 1]));
                        if ((z & need) == need) break;
                        if (++tries > 100000000L) { okc = 0; break; }
                    }
                }
                if (!okc) continue;
                rc[i].x[0] = xe; rc[i].y[0] = ye; rc[i].x[1] = xo[0]; rc[i].y[1] = yo[0]; rc[i].x[2] = xo[1]; rc[i].y[2] = yo[1];
                break;
            }
        }
        /* (a) correct key consistent with both */
        int correct_ok = 1;
        for (int i = 0; i < 2; i++) {
            int z[3]; for (int c = 0; c < 3; c++) z[c] = zmask32(colimg(rc[i].x[c] ^ k[c]) ^ colimg(rc[i].y[c] ^ k[c]));
            if (!consistent(z[0], z[1], z[2])) correct_ok = 0;
        }
        /* (b)+(c): per-column zero-mask histograms over all 2^32 guesses, for both right classes jointly */
        uint64_t H[3][256]; int tb[3];
        for (int c = 0; c < 3; c++) scan_col_pairs(&rc[0], &rc[1], c, H[c], k[c], &tb[c]);
        /* probability that a random 96-bit guess satisfies the condition of right class 0 (and of class 1) */
        double p0 = 0, p1 = 0; const double N32 = 4294967296.0;
        /* marginals per column for pair 0 / pair 1 */
        double me0[16] = {0}, me1[16] = {0}, m10[16] = {0}, m11[16] = {0}, m20[16] = {0}, m21[16] = {0};
        for (int a = 0; a < 16; a++) for (int b = 0; b < 16; b++) {
            me0[a] += H[0][a * 16 + b]; me1[b] += H[0][a * 16 + b];
            m10[a] += H[1][a * 16 + b]; m11[b] += H[1][a * 16 + b];
            m20[a] += H[2][a * 16 + b]; m21[b] += H[2][a * 16 + b];
        }
        for (int ze = 0; ze < 16; ze++) for (int z1 = 0; z1 < 16; z1++) for (int z2 = 0; z2 < 16; z2++) {
            if (consistent(ze, z1, z2)) { p0 += me0[ze] / N32 * m10[z1] / N32 * m20[z2] / N32; p1 += me1[ze] / N32 * m11[z1] / N32 * m21[z2] / N32; }
        }
        /* (c) exact count of guesses consistent with BOTH pairs: product over columns of joint histograms, summed over consistent (ze,z1,z2) x (ze',z1',z2') */
        long double cand = 0;
        for (int ae = 0; ae < 256; ae++) { if (!H[0][ae]) continue;
            for (int a1 = 0; a1 < 256; a1++) { if (!H[1][a1]) continue;
                for (int a2 = 0; a2 < 256; a2++) { if (!H[2][a2]) continue;
                    if (consistent(ae >> 4, a1 >> 4, a2 >> 4) && consistent(ae & 15, a1 & 15, a2 & 15))
                        cand += (long double)H[0][ae] * H[1][a1] * H[2][a2];
                } } }
        int true_in = consistent(tb[0] >> 4, tb[1] >> 4, tb[2] >> 4) && consistent(tb[0] & 15, tb[1] & 15, tb[2] & 15);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double secs = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
        printf("%ld,%llu,%d,%.4f,%.4f,%.4f,%.2f,%d,%.0f\n", t, (unsigned long long)seed, correct_ok, log2(p0), log2(p1), log2(sqrt(p0 * p1)), (double)log2l(cand), true_in, secs);
        fflush(stdout);
    }
    return 0;
}

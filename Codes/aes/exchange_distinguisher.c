/*
 * exchange_distinguisher.c -- fast full-AES exchange distinguisher experiment (re-implementation
 * of exchange_distinguisher.c for large trial counts).
 *
 * Structure: diagonal 0 (bytes 0,5,10,15) takes M = 2^L values A[i], diagonal 1
 * (bytes 3,4,9,14) takes M values B[j], the other bytes are a random constant.
 * Text index idx = (i << L) | j.  For each of the 4 inverse diagonals (the
 * PASSIVE_SETS of the original code) we find all colliding pairs, skip pairs
 * that are equal on diagonal 0 or on diagonal 1 (value comparison, exactly as
 * the flag0/flag1 test of the original), and test the diagonal-1-exchanged pair
 * ((i1,j2),(i2,j1)) by table lookup instead of re-encryption.
 *
 * RNG modes
 *   0 : splitmix64 per trial (seed, trial); distinct diagonal values.
 *   1 : glibc rand() after srand(seed), consumed in exactly the order of the
 *       original program (mk/pt interleaved, then diag0, then diag1, with
 *       replacement), so a run with seed S reproduces the original binary
 *       patched with srand(S).
 *
 * Per trial it also computes, without encryption, M_S = number of classes of the
 * structure satisfying the one-round exchange condition Eq.(1) under the real
 * k0, and lambda_S = M_S*q + #classes*2^-62, and classifies every detected class
 * as trail / non-trail.
 *
 * Usage: distinguisher R L trials mode seed [first_trial] [pairlog_threshold]
 * Output (stdout, one CSV line per trial):
 *   trial,mode,seed,pairs,classes,trail_classes,M_S,lambda_S,dupA,dupB,deg_collide,parity_ok,secs
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <immintrin.h>

static const int PASSIVE_SETS[4][4] = {{3, 6, 9, 12}, {2, 5, 8, 15}, {1, 4, 11, 14}, {0, 7, 10, 13}};
static const int IDX1[4] = {0, 5, 10, 15};   /* diagonal 0 */
static const int IDX2[4] = {3, 4, 9, 14};    /* diagonal 1 (order of the original code) */

static __m128i key_exp(__m128i key, __m128i kg) {
    kg = _mm_shuffle_epi32(kg, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, kg);
}
#define KEXP(k, rc) key_exp(k, _mm_aeskeygenassist_si128(k, rc))

static uint64_t sm_s;
static inline uint64_t sm64(void) {
    uint64_t z = (sm_s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static int VALID[16][16];
static void init_valid(void) {
    for (int z0 = 0; z0 < 16; z0++)
        for (int z1 = 0; z1 < 16; z1++) {
            int ok = 0;
            for (int v = 1; v <= 14 && !ok; v++) {
                int need0 = 0, on1 = 0;
                for (int d = 0; d < 4; d++)
                    if ((v >> d) & 1) { need0 |= 1 << ((4 - d) & 3); on1 |= 1 << ((1 - d) & 3); }
                int need1 = (~on1) & 0xF;
                if ((z0 & need0) == need0 && (z1 & need1) == need1) ok = 1;
            }
            VALID[z0][z1] = ok;
        }
}
static inline int zmask32(uint32_t d) {   /* bit r set iff byte r (row r) is zero */
    int z = 0;
    for (int r = 0; r < 4; r++) if (((d >> (8 * r)) & 0xFF) == 0) z |= 1 << r;
    return z;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}
/* H[z] = #index pairs whose column-image difference has zero-mask exactly z */
static void zero_hist(const uint32_t *col, int m, double H[16]) {
    double N[16];
    uint32_t *tmp = malloc(sizeof(uint32_t) * m);
    for (int R = 0; R < 16; R++) {
        uint32_t mask = 0;
        for (int r = 0; r < 4; r++) if ((R >> r) & 1) mask |= 0xFFu << (8 * r);
        for (int i = 0; i < m; i++) tmp[i] = col[i] & mask;
        qsort(tmp, m, sizeof(uint32_t), cmp_u32);
        double s = 0; int run = 1;
        for (int i = 1; i <= m; i++) {
            if (i < m && tmp[i] == tmp[i - 1]) run++;
            else { s += (double)run * (run - 1) / 2; run = 1; }
        }
        N[R] = s;
    }
    free(tmp);
    for (int z = 0; z < 16; z++) {
        H[z] = 0;
        for (int R = 0; R < 16; R++)
            if ((R & z) == z) H[z] += ((__builtin_popcount(R) - __builtin_popcount(z)) & 1 ? -1 : 1) * N[R];
    }
}

static void radix_sort_hi32(uint64_t *a, uint64_t *buf, uint64_t n) {
    static const int sh[3] = {32, 43, 54}, bits[3] = {11, 11, 10};
    static uint64_t cnt[2048];
    for (int p = 0; p < 3; p++) {
        int nb = 1 << bits[p]; uint64_t mask = nb - 1;
        memset(cnt, 0, sizeof(uint64_t) * nb);
        for (uint64_t i = 0; i < n; i++) cnt[(a[i] >> sh[p]) & mask]++;
        uint64_t s = 0;
        for (int b = 0; b < nb; b++) { uint64_t c = cnt[b]; cnt[b] = s; s += c; }
        for (uint64_t i = 0; i < n; i++) buf[cnt[(a[i] >> sh[p]) & mask]++] = a[i];
        uint64_t *t = a; a = buf; buf = t;
    }
    /* odd number of passes: the sorted data ends up in the caller's buf */
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: distinguisher R L trials mode seed [first_trial] [pairlog_thr]\n"); return 1; }
    int R = atoi(argv[1]), L = atoi(argv[2]);
    long trials = atol(argv[3]); int mode = atoi(argv[4]);
    uint64_t seed = strtoull(argv[5], NULL, 10);
    long first = argc > 6 ? atol(argv[6]) : 0;
    long logthr = argc > 7 ? atol(argv[7]) : 4;
    uint64_t M = 1ULL << L, N = M * M;
    init_valid();

    uint8_t (*A)[4] = malloc(4 * M), (*B)[4] = malloc(4 * M);
    uint32_t *XA = malloc(4 * M), *XB = malloc(4 * M);
    __m128i *VA = _mm_malloc(16 * M, 16), *VB = _mm_malloc(16 * M, 16);
    uint32_t *F = malloc(sizeof(uint32_t) * N);
    uint64_t *P = malloc(sizeof(uint64_t) * N), *Q = malloc(sizeof(uint64_t) * N);
    if (!A || !B || !F || !P || !Q || !VA || !VB) { fprintf(stderr, "alloc failed\n"); return 1; }
    if (mode == 1) srand((unsigned)seed);
    const double q = 1.0 - (1.0 - 1.0 / 4294967296.0) * (1.0 - 1.0 / 4294967296.0) * (1.0 - 1.0 / 4294967296.0) * (1.0 - 1.0 / 4294967296.0);

    for (long t = first; t < first + trials; t++) {
        struct timespec ts0, ts1; clock_gettime(CLOCK_MONOTONIC, &ts0);
        uint8_t mk[16], pt[16];
        if (mode == 1) {
            for (int i = 0; i < 16; i++) { mk[i] = rand() % 256; pt[i] = rand() % 256; }
            for (uint64_t i = 0; i < M; i++) for (int b = 0; b < 4; b++) A[i][b] = rand() & 0xFF;
            for (uint64_t j = 0; j < M; j++) for (int b = 0; b < 4; b++) B[j][b] = rand() & 0xFF;
        } else {
            sm_s = seed * 0x100000001B3ULL ^ (uint64_t)t * 0xD6E8FEB86659FD93ULL; sm64(); sm64();
            for (int i = 0; i < 16; i++) { mk[i] = (uint8_t)sm64(); pt[i] = (uint8_t)sm64(); }
            /* distinct values: rejection with a small open-addressing set */
            uint64_t hs = 4 * M; uint32_t *set = calloc(hs, 4); uint8_t *used = calloc(hs, 1);
            for (int w = 0; w < 2; w++) {
                memset(used, 0, hs);
                for (uint64_t i = 0; i < M; i++) {
                    for (;;) {
                        uint32_t v = (uint32_t)sm64();
                        uint64_t h = ((uint64_t)v * 0x9E3779B97F4A7C15ULL) % hs; int dup = 0;
                        while (used[h]) { if (set[h] == v) { dup = 1; break; } h = (h + 1) % hs; }
                        if (dup) continue;
                        used[h] = 1; set[h] = v;
                        uint8_t *dst = w ? B[i] : A[i];
                        for (int b = 0; b < 4; b++) dst[b] = (uint8_t)(v >> (8 * b));
                        break;
                    }
                }
            }
            free(set); free(used);
        }
        __m128i rk[11];
        rk[0] = _mm_loadu_si128((const __m128i *)mk);
        rk[1] = KEXP(rk[0], 0x01); rk[2] = KEXP(rk[1], 0x02); rk[3] = KEXP(rk[2], 0x04); rk[4] = KEXP(rk[3], 0x08);
        rk[5] = KEXP(rk[4], 0x10); rk[6] = KEXP(rk[5], 0x20); rk[7] = KEXP(rk[6], 0x40); rk[8] = KEXP(rk[7], 0x80);
        rk[9] = KEXP(rk[8], 0x1B); rk[10] = KEXP(rk[9], 0x36);

        uint8_t base0[16]; memcpy(base0, pt, 16);
        for (int b = 0; b < 4; b++) { base0[IDX1[b]] = 0; base0[IDX2[b]] = 0; }
        __m128i baseK = _mm_xor_si128(_mm_loadu_si128((const __m128i *)base0), rk[0]);
        for (uint64_t i = 0; i < M; i++) {
            uint8_t v[16] = {0}; for (int b = 0; b < 4; b++) v[IDX1[b]] = A[i][b];
            VA[i] = _mm_loadu_si128((const __m128i *)v);
            __m128i s = _mm_aesenc_si128(_mm_xor_si128(VA[i], rk[0]), _mm_setzero_si128());
            uint8_t o[16]; _mm_storeu_si128((__m128i *)o, s);
            XA[i] = (uint32_t)o[0] | (uint32_t)o[1] << 8 | (uint32_t)o[2] << 16 | (uint32_t)o[3] << 24;   /* column 0 */
        }
        for (uint64_t j = 0; j < M; j++) {
            uint8_t v[16] = {0}; for (int b = 0; b < 4; b++) v[IDX2[b]] = B[j][b];
            VB[j] = _mm_loadu_si128((const __m128i *)v);
            __m128i s = _mm_aesenc_si128(_mm_xor_si128(VB[j], rk[0]), _mm_setzero_si128());
            uint8_t o[16]; _mm_storeu_si128((__m128i *)o, s);
            XB[j] = (uint32_t)o[4] | (uint32_t)o[5] << 8 | (uint32_t)o[6] << 16 | (uint32_t)o[7] << 24;   /* column 1 */
        }
        /* exact M_S and lambda_S */
        double Ha[16], Hb[16];
        zero_hist(XA, (int)M, Ha); zero_hist(XB, (int)M, Hb);
        double dupA = Ha[15], dupB = Hb[15]; Ha[15] = 0; Hb[15] = 0;
        double Ms = 0;
        for (int a = 0; a < 16; a++) for (int b = 0; b < 16; b++) if (VALID[a][b]) Ms += Ha[a] * Hb[b];
        double ncls = ((double)M * (M - 1) / 2 - dupA) * ((double)M * (M - 1) / 2 - dupB);
        double lam = Ms * q + ncls / 4294967296.0 / 1073741824.0;   /* random term: ncls * 2^-62 */

        uint64_t pairs = 0, trailpairs = 0, degcol = 0;
        for (int k = 0; k < 4; k++) {
            __m128i shuf = _mm_setr_epi8(PASSIVE_SETS[k][0], PASSIVE_SETS[k][1], PASSIVE_SETS[k][2], PASSIVE_SETS[k][3],
                                         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
            for (uint64_t i = 0; i < M; i++) {
                __m128i pa = _mm_xor_si128(VA[i], baseK);
                uint64_t off = i << L;
                for (uint64_t j = 0; j < M; j += 8) {
                    __m128i s0 = _mm_xor_si128(pa, VB[j]), s1 = _mm_xor_si128(pa, VB[j + 1]), s2 = _mm_xor_si128(pa, VB[j + 2]), s3 = _mm_xor_si128(pa, VB[j + 3]);
                    __m128i s4 = _mm_xor_si128(pa, VB[j + 4]), s5 = _mm_xor_si128(pa, VB[j + 5]), s6 = _mm_xor_si128(pa, VB[j + 6]), s7 = _mm_xor_si128(pa, VB[j + 7]);
                    for (int r = 1; r < R; r++) {
                        s0 = _mm_aesenc_si128(s0, rk[r]); s1 = _mm_aesenc_si128(s1, rk[r]); s2 = _mm_aesenc_si128(s2, rk[r]); s3 = _mm_aesenc_si128(s3, rk[r]);
                        s4 = _mm_aesenc_si128(s4, rk[r]); s5 = _mm_aesenc_si128(s5, rk[r]); s6 = _mm_aesenc_si128(s6, rk[r]); s7 = _mm_aesenc_si128(s7, rk[r]);
                    }
                    s0 = _mm_aesenclast_si128(s0, rk[R]); s1 = _mm_aesenclast_si128(s1, rk[R]); s2 = _mm_aesenclast_si128(s2, rk[R]); s3 = _mm_aesenclast_si128(s3, rk[R]);
                    s4 = _mm_aesenclast_si128(s4, rk[R]); s5 = _mm_aesenclast_si128(s5, rk[R]); s6 = _mm_aesenclast_si128(s6, rk[R]); s7 = _mm_aesenclast_si128(s7, rk[R]);
                    uint32_t f[8];
                    f[0] = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s0, shuf)); f[1] = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s1, shuf));
                    f[2] = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s2, shuf)); f[3] = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s3, shuf));
                    f[4] = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s4, shuf)); f[5] = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s5, shuf));
                    f[6] = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s6, shuf)); f[7] = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s7, shuf));
                    for (int u = 0; u < 8; u++) { uint64_t idx = off | (j + u); F[idx] = f[u]; P[idx] = ((uint64_t)f[u] << 32) | idx; }
                }
            }
            radix_sort_hi32(P, Q, N);   /* sorted result in Q */
            uint64_t s = 0;
            while (s < N) {
                uint64_t e = s + 1; uint32_t fv = (uint32_t)(Q[s] >> 32);
                while (e < N && (uint32_t)(Q[e] >> 32) == fv) e++;
                for (uint64_t a = s; a < e; a++)
                    for (uint64_t b = a + 1; b < e; b++) {
                        uint64_t x = Q[a] & 0xFFFFFFFFULL, y = Q[b] & 0xFFFFFFFFULL;
                        uint64_t i1 = x >> L, j1 = x & (M - 1), i2 = y >> L, j2 = y & (M - 1);
                        if (!memcmp(A[i1], A[i2], 4) || !memcmp(B[j1], B[j2], 4)) { degcol++; continue; }
                        if (F[(i1 << L) | j2] == F[(i2 << L) | j1]) {
                            pairs++;
                            int z0 = zmask32(XA[i1] ^ XA[i2]), z1 = zmask32(XB[j1] ^ XB[j2]);
                            int tr = VALID[z0][z1];
                            trailpairs += tr;
                            if (logthr) fprintf(stderr, "RP t=%ld k=%d i1=%llu j1=%llu i2=%llu j2=%llu trail=%d z0=%x z1=%x\n", t, k,
                                    (unsigned long long)i1, (unsigned long long)j1, (unsigned long long)i2, (unsigned long long)j2, tr, z0, z1);
                        }
                    }
                s = e;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        double secs = (ts1.tv_sec - ts0.tv_sec) + 1e-9 * (ts1.tv_nsec - ts0.tv_nsec);
        printf("%ld,%d,%llu,%llu,%llu,%llu,%.0f,%.6f,%.0f,%.0f,%llu,%d,%.1f\n", t, mode, (unsigned long long)seed,
               (unsigned long long)pairs, (unsigned long long)(pairs / 2), (unsigned long long)(trailpairs / 2),
               Ms, lam, dupA, dupB, (unsigned long long)degcol, (int)((pairs & 1) == 0), secs);
        fflush(stdout); fflush(stderr);
    }
    return 0;
}

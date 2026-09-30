/*
 * exchange_keyrecovery.c -- end-to-end key recovery on 5-round AES from exchange classes.
 *
 * Algorithm 3 of the paper: exact one-round pattern filter (Eq.(1) <=> one of 14
 * zero patterns of Observation 1 in the two active columns after the first MC)
 * and the key-candidate selection rule "candidates = guesses with count >= 2,
 * ranked by count", where the count of a guess is the number of detected classes
 * whose pattern it satisfies; the rule tolerates detected classes that are not
 * right classes.  The weak test of the previously submitted version ("at least
 * one zero byte in each active column", all classes must pass) is evaluated on
 * the true key for comparison (column weak_strict_ok).
 *
 * Structure s=0: diagonals 0,1 active, exchange diagonal 1 -> k0 diagonals 0,1
 * Structure s=1: diagonals 2,3 active, exchange diagonal 3 -> k0 diagonals 2,3
 * M distinct random 32-bit values per active diagonal; D = M^2 texts per
 * structure; text index idx = i*M + j.
 *
 * Usage: key_recovery M attacks seed first threads
 * Output (CSV per attack):
 *  attack,seed,M,n0,f0,n1,f1,cons0,cons1,cand0,cand1,top0,ntop0,nge0,top1,ntop1,nge1,
 *  log2_total,log2_tiered,found,weak_strict_ok,secs
 *  n = detected classes, f = detected classes that are not right classes,
 *  cons = count of the true key (number of detected classes whose pattern it
 *  satisfies), cand = size of the candidate list for the 64 key bits of the
 *  structure, top/ntop = highest count and its multiplicity, nge = #candidates
 *  ranked at least as high as the true key (cost of the ranked search),
 *  found = true key recovered (by trial encryption of one of the chosen
 *  plaintexts when |L0|*|L1| <= 2^28, otherwise = present in both lists).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <immintrin.h>
#include <omp.h>

static const int PASSIVE_SETS[4][4] = {{3, 6, 9, 12}, {2, 5, 8, 15}, {1, 4, 11, 14}, {0, 7, 10, 13}};
static uint8_t SBOX[256];
static uint32_t TE[4][256];   /* TE[r][x] = MixColumns column r * S(x); byte k of the word = row k */

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
            for (int k = 0; k < 4; k++) {
                int c = MCm[k][r];
                uint8_t b = c == 1 ? s : (c == 2 ? s2 : s3);
                w |= (uint32_t)b << (8 * k);
            }
            TE[r][x] = w;
        }
}
static inline uint32_t colimg(uint32_t a) {   /* MC(S(a)) for a column whose row r is byte r of a */
    return TE[0][a & 0xFF] ^ TE[1][(a >> 8) & 0xFF] ^ TE[2][(a >> 16) & 0xFF] ^ TE[3][a >> 24];
}
static inline int zmask32(uint32_t v) {       /* bit r set iff byte r of v is zero */
    uint32_t t = (v & 0x7F7F7F7Fu) + 0x7F7F7F7Fu;
    t = ~(t | v | 0x7F7F7F7Fu);
    return (int)(((t >> 7) & 1) | ((t >> 14) & 2) | ((t >> 21) & 4) | ((t >> 28) & 8));
}
static inline int diag_byte(int d, int r) { return 4 * ((r + d) & 3) + r; }

static __m128i key_exp(__m128i key, __m128i kg) {
    kg = _mm_shuffle_epi32(kg, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, kg);
}
#define KEXP(k, rc) key_exp(k, _mm_aeskeygenassist_si128(k, rc))
static void expand(const uint8_t mk[16], __m128i rk[11]) {
    rk[0] = _mm_loadu_si128((const __m128i *)mk);
    rk[1] = KEXP(rk[0], 0x01); rk[2] = KEXP(rk[1], 0x02); rk[3] = KEXP(rk[2], 0x04); rk[4] = KEXP(rk[3], 0x08);
    rk[5] = KEXP(rk[4], 0x10); rk[6] = KEXP(rk[5], 0x20); rk[7] = KEXP(rk[6], 0x40); rk[8] = KEXP(rk[7], 0x80);
    rk[9] = KEXP(rk[8], 0x1B); rk[10] = KEXP(rk[9], 0x36);
}
static inline __m128i enc5(__m128i p, const __m128i rk[11]) {
    __m128i s = _mm_xor_si128(p, rk[0]);
    for (int r = 1; r < 5; r++) s = _mm_aesenc_si128(s, rk[r]);
    return _mm_aesenclast_si128(s, rk[5]);
}

static uint64_t sm_s;
static inline uint64_t sm64(void) {
    uint64_t z = (sm_s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void gen_distinct(uint32_t *X, uint64_t M) {
    uint64_t hs = 4 * M; uint32_t *set = calloc(hs, 4); uint8_t *used = calloc(hs, 1);
    for (uint64_t i = 0; i < M; i++)
        for (;;) {
            uint32_t v = (uint32_t)sm64();
            uint64_t h = ((uint64_t)v * 0x9E3779B97F4A7C15ULL) % hs; int dup = 0;
            while (used[h]) { if (set[h] == v) { dup = 1; break; } h = (h + 1) % hs; }
            if (dup) continue;
            used[h] = 1; set[h] = v; X[i] = v; break;
        }
    free(set); free(used);
}

/* V[zx][zy]: structure with active diagonals dx, dy, exchange of dy */
static void make_valid(int dx, int dy, int V[16][16]) {
    for (int zx = 0; zx < 16; zx++)
        for (int zy = 0; zy < 16; zy++) {
            int ok = 0;
            for (int v = 1; v <= 14 && !ok; v++) {
                int needx = 0, ony = 0;
                for (int d = 0; d < 4; d++)
                    if ((v >> d) & 1) { needx |= 1 << ((dx - d) & 3); ony |= 1 << ((dy - d) & 3); }
                int needy = (~ony) & 0xF;
                if ((zx & needx) == needx && (zy & needy) == needy) ok = 1;
            }
            V[zx][zy] = ok;
        }
}

static void radix_sort_hi32(uint64_t *a, uint64_t *buf, uint64_t n) {   /* result ends in buf */
    static const int sh[3] = {32, 43, 54}, bits[3] = {11, 11, 10};
    uint64_t *cnt = malloc(sizeof(uint64_t) * 2048);
    for (int p = 0; p < 3; p++) {
        int nb = 1 << bits[p]; uint64_t mask = nb - 1;
        memset(cnt, 0, sizeof(uint64_t) * nb);
        for (uint64_t i = 0; i < n; i++) cnt[(a[i] >> sh[p]) & mask]++;
        uint64_t s = 0;
        for (int b = 0; b < nb; b++) { uint64_t c = cnt[b]; cnt[b] = s; s += c; }
        for (uint64_t i = 0; i < n; i++) buf[cnt[(a[i] >> sh[p]) & mask]++] = a[i];
        uint64_t *t = a; a = buf; buf = t;
    }
    free(cnt);
}

typedef struct { uint32_t a1, a2, b1, b2; int trail; } cls_t;
#define MAXC 16

static int collect(int dx, int dy, uint64_t M, const __m128i rk[11], const uint8_t mk[16],
                   uint32_t *F, uint64_t *P, uint64_t *Q, cls_t *out, int V[16][16], int *nfalse) {
    uint64_t N = M * M;
    uint32_t *A = malloc(4 * M), *B = malloc(4 * M);
    gen_distinct(A, M); gen_distinct(B, M);
    uint8_t base[16]; for (int b = 0; b < 16; b++) base[b] = (uint8_t)sm64();
    for (int r = 0; r < 4; r++) { base[diag_byte(dx, r)] = 0; base[diag_byte(dy, r)] = 0; }
    __m128i baseK = _mm_xor_si128(_mm_loadu_si128((const __m128i *)base), rk[0]);
    __m128i *VA = _mm_malloc(16 * M, 16), *VB = _mm_malloc(16 * M, 16);
    for (uint64_t i = 0; i < M; i++) {
        uint8_t v[16] = {0}; for (int r = 0; r < 4; r++) v[diag_byte(dx, r)] = (uint8_t)(A[i] >> (8 * r));
        VA[i] = _mm_loadu_si128((const __m128i *)v);
        uint8_t w[16] = {0}; for (int r = 0; r < 4; r++) w[diag_byte(dy, r)] = (uint8_t)(B[i] >> (8 * r));
        VB[i] = _mm_loadu_si128((const __m128i *)w);
    }
    uint32_t kx = 0, ky = 0;
    for (int r = 0; r < 4; r++) { kx |= (uint32_t)mk[diag_byte(dx, r)] << (8 * r); ky |= (uint32_t)mk[diag_byte(dy, r)] << (8 * r); }
    int n = 0; *nfalse = 0;
    for (int k = 0; k < 4; k++) {
        __m128i shuf = _mm_setr_epi8(PASSIVE_SETS[k][0], PASSIVE_SETS[k][1], PASSIVE_SETS[k][2], PASSIVE_SETS[k][3],
                                     -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
        #pragma omp parallel for schedule(static)
        for (uint64_t i = 0; i < M; i++) {
            __m128i pa = _mm_xor_si128(VA[i], baseK);
            uint64_t off = i * M;
            for (uint64_t j = 0; j < M; j += 8) {
                __m128i s[8];
                for (int u = 0; u < 8; u++) s[u] = _mm_xor_si128(pa, VB[j + u]);
                for (int r = 1; r < 5; r++) for (int u = 0; u < 8; u++) s[u] = _mm_aesenc_si128(s[u], rk[r]);
                for (int u = 0; u < 8; u++) {
                    s[u] = _mm_aesenclast_si128(s[u], rk[5]);
                    uint32_t f = (uint32_t)_mm_cvtsi128_si32(_mm_shuffle_epi8(s[u], shuf));
                    uint64_t idx = off + j + u;
                    F[idx] = f; P[idx] = ((uint64_t)f << 32) | idx;
                }
            }
        }
        radix_sort_hi32(P, Q, N);
        uint64_t s = 0;
        while (s < N) {
            uint64_t e = s + 1; uint32_t fv = (uint32_t)(Q[s] >> 32);
            while (e < N && (uint32_t)(Q[e] >> 32) == fv) e++;
            for (uint64_t a = s; a < e; a++)
                for (uint64_t b = a + 1; b < e; b++) {
                    uint64_t x = Q[a] & 0xFFFFFFFFULL, y = Q[b] & 0xFFFFFFFFULL;
                    uint64_t i1 = x / M, j1 = x % M, i2 = y / M, j2 = y % M;
                    if (i1 == i2 || j1 == j2) continue;          /* degenerate (values are distinct) */
                    if (F[i1 * M + j2] != F[i2 * M + j1]) continue;
                    if (i1 > i2) { uint64_t t = i1; i1 = i2; i2 = t; t = j1; j1 = j2; j2 = t; }
                    if (j1 > j2) continue;                      /* one representative per class */
                    if (n < MAXC) {
                        cls_t *c = &out[n++];
                        c->a1 = A[i1]; c->a2 = A[i2]; c->b1 = B[j1]; c->b2 = B[j2];
                        int zx = zmask32(colimg(c->a1 ^ kx) ^ colimg(c->a2 ^ kx));
                        int zy = zmask32(colimg(c->b1 ^ ky) ^ colimg(c->b2 ^ ky));
                        c->trail = V[zx][zy];
                        if (!c->trail) (*nfalse)++;
                    }
                }
            s = e;
        }
    }
    free(A); free(B); _mm_free(VA); _mm_free(VB);
    return n;
}

typedef struct { uint32_t g; uint64_t z; } gz_t;   /* key guess and packed per-class zero masks */

/* all 32-bit guesses g of one key diagonal with >= 2 classes having a nonzero zero-mask */
static gz_t *scan_diag(const uint32_t *u1, const uint32_t *u2, int n, uint64_t *cnt_out) {
    uint32_t (*DT)[4][256] = malloc(sizeof(uint32_t[4][256]) * n);
    for (int c = 0; c < n; c++)
        for (int r = 0; r < 4; r++)
            for (int x = 0; x < 256; x++)
                DT[c][r][x] = TE[r][((u1[c] >> (8 * r)) & 0xFF) ^ x] ^ TE[r][((u2[c] >> (8 * r)) & 0xFF) ^ x];
    int T = omp_get_max_threads();
    gz_t **loc = calloc(T, sizeof(gz_t *)); uint64_t *lcnt = calloc(T, 8), *lcap = calloc(T, 8);
    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        lcap[tid] = 1 << 16; loc[tid] = malloc(sizeof(gz_t) * lcap[tid]);
        #pragma omp for schedule(dynamic, 256)
        for (uint32_t hi = 0; hi < (1u << 24); hi++) {       /* g3 g2 g1 */
            uint32_t g1 = hi & 0xFF, g2 = (hi >> 8) & 0xFF, g3 = hi >> 16;
            uint32_t part[MAXC];
            for (int c = 0; c < n; c++) part[c] = DT[c][1][g1] ^ DT[c][2][g2] ^ DT[c][3][g3];
            for (uint32_t g0 = 0; g0 < 256; g0++) {
                uint64_t z = 0; int nz = 0;
                for (int c = 0; c < n; c++) {
                    int zm = zmask32(part[c] ^ DT[c][0][g0]);
                    z |= (uint64_t)zm << (4 * c); nz += (zm != 0);
                }
                if (nz >= 2) {
                    if (lcnt[tid] == lcap[tid]) { lcap[tid] *= 2; loc[tid] = realloc(loc[tid], sizeof(gz_t) * lcap[tid]); }
                    loc[tid][lcnt[tid]].g = g0 | (g1 << 8) | (g2 << 16) | (g3 << 24);
                    loc[tid][lcnt[tid]].z = z; lcnt[tid]++;
                }
            }
        }
    }
    uint64_t tot = 0; for (int t = 0; t < T; t++) tot += lcnt[t];
    gz_t *res = malloc(sizeof(gz_t) * (tot + 1)); uint64_t p = 0;
    for (int t = 0; t < T; t++) { memcpy(res + p, loc[t], sizeof(gz_t) * lcnt[t]); p += lcnt[t]; free(loc[t]); }
    free(loc); free(lcnt); free(lcap); free(DT);
    *cnt_out = tot;
    return res;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return (x > y) - (x < y);
}

/* candidate key pairs (gx<<32|gy) consistent with >= 2 classes; returns sorted unique list */
static uint64_t *candidates(const cls_t *cl, int n, int dxV[16][16], uint64_t *ncand) {
    uint32_t u1[MAXC], u2[MAXC], w1[MAXC], w2[MAXC];
    for (int c = 0; c < n; c++) { u1[c] = cl[c].a1; u2[c] = cl[c].a2; w1[c] = cl[c].b1; w2[c] = cl[c].b2; }
    uint64_t nx, ny;
    gz_t *Sx = scan_diag(u1, u2, n, &nx), *Sy = scan_diag(w1, w2, n, &ny);
    uint64_t cap = 1 << 16, cnt = 0; uint64_t *C = malloc(8 * cap);
    uint32_t *gx = malloc(4 * (nx + 1)), *gy = malloc(4 * (ny + 1));
    for (int c1 = 0; c1 < n; c1++)
        for (int c2 = c1 + 1; c2 < n; c2++) {
            /* counting-sort Sx and Sy into buckets keyed by (z_c1, z_c2); zero masks can never be valid */
            uint64_t bx[257] = {0}, by[257] = {0};
            for (uint64_t t = 0; t < nx; t++) bx[1 + (((Sx[t].z >> (4 * c1)) & 15) << 4 | ((Sx[t].z >> (4 * c2)) & 15))]++;
            for (uint64_t t = 0; t < ny; t++) by[1 + (((Sy[t].z >> (4 * c1)) & 15) << 4 | ((Sy[t].z >> (4 * c2)) & 15))]++;
            for (int b = 0; b < 256; b++) { bx[b + 1] += bx[b]; by[b + 1] += by[b]; }
            uint64_t px[256], py[256];
            memcpy(px, bx, sizeof px); memcpy(py, by, sizeof py);
            for (uint64_t t = 0; t < nx; t++) gx[px[((Sx[t].z >> (4 * c1)) & 15) << 4 | ((Sx[t].z >> (4 * c2)) & 15)]++] = Sx[t].g;
            for (uint64_t t = 0; t < ny; t++) gy[py[((Sy[t].z >> (4 * c1)) & 15) << 4 | ((Sy[t].z >> (4 * c2)) & 15)]++] = Sy[t].g;
            for (int kxk = 0; kxk < 256; kxk++) {
                if (bx[kxk + 1] == bx[kxk]) continue;
                int zx1 = kxk >> 4, zx2 = kxk & 15;
                for (int kyk = 0; kyk < 256; kyk++) {
                    if (by[kyk + 1] == by[kyk]) continue;
                    int zy1 = kyk >> 4, zy2 = kyk & 15;
                    if (!(dxV[zx1][zy1] && dxV[zx2][zy2])) continue;
                    for (uint64_t a = bx[kxk]; a < bx[kxk + 1]; a++)
                        for (uint64_t b = by[kyk]; b < by[kyk + 1]; b++) {
                            if (cnt == cap) { cap *= 2; C = realloc(C, 8 * cap); }
                            C[cnt++] = ((uint64_t)gx[a] << 32) | gy[b];
                        }
                }
            }
        }
    free(gx); free(gy); free(Sx); free(Sy);
    qsort(C, cnt, 8, cmp_u64);
    uint64_t u = 0;
    for (uint64_t t = 0; t < cnt; t++) if (t == 0 || C[t] != C[t - 1]) C[u++] = C[t];
    *ncand = u;
    return C;
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: key_recovery M attacks seed first threads [nt nf]  (M=0: synthetic classes)\n"); return 1; }
    uint64_t M = strtoull(argv[1], NULL, 10); long attacks = atol(argv[2]);
    uint64_t seed = strtoull(argv[3], NULL, 10); long first = atol(argv[4]); int threads = atoi(argv[5]);
    int syn_nt = argc > 6 ? atoi(argv[6]) : 4, syn_nf = argc > 7 ? atoi(argv[7]) : 1;
    if (M % 8) { fprintf(stderr, "M must be a multiple of 8\n"); return 1; }
    omp_set_num_threads(threads);
    init_tables();
    uint64_t N = M * M;
    uint32_t *F = NULL; uint64_t *P = NULL, *Q = NULL;
    if (M) {
        F = malloc(4 * N); P = malloc(8 * N); Q = malloc(8 * N);
        if (!F || !P || !Q) { fprintf(stderr, "alloc failed\n"); return 1; }
    }
    int V[2][16][16]; make_valid(0, 1, V[0]); make_valid(2, 3, V[1]);
    for (long at = first; at < first + attacks; at++) {
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        sm_s = seed * 0x100000001B3ULL ^ (uint64_t)at * 0xD6E8FEB86659FD93ULL; sm64(); sm64();
        uint8_t mk[16]; for (int b = 0; b < 16; b++) mk[b] = (uint8_t)sm64();
        __m128i rk[11]; expand(mk, rk);
        cls_t cl[2][MAXC]; int n[2], f[2];
        uint32_t kd[4];
        for (int d = 0; d < 4; d++) { kd[d] = 0; for (int r = 0; r < 4; r++) kd[d] |= (uint32_t)mk[diag_byte(d, r)] << (8 * r); }
        if (M) {
            n[0] = collect(0, 1, M, rk, mk, F, P, Q, cl[0], V[0], &f[0]);
            n[1] = collect(2, 3, M, rk, mk, F, P, Q, cl[1], V[1], &f[1]);
        } else {
            /* synthetic test: syn_nt trail classes (Eq.(1) holds under k0, by rejection sampling)
             * plus syn_nf random classes per structure */
            for (int s = 0; s < 2; s++) {
                n[s] = 0; f[s] = 0;
                uint32_t kx = kd[2 * s], ky = kd[2 * s + 1];
                for (int c = 0; c < syn_nt + syn_nf && c < MAXC; c++) {
                    cls_t *x = &cl[s][n[s]];
                    for (;;) {
                        x->a1 = (uint32_t)sm64(); x->a2 = (uint32_t)sm64(); x->b1 = (uint32_t)sm64(); x->b2 = (uint32_t)sm64();
                        if (x->a1 == x->a2 || x->b1 == x->b2) continue;
                        int zx = zmask32(colimg(x->a1 ^ kx) ^ colimg(x->a2 ^ kx));
                        if (c < syn_nt && !zx) continue;
                        int zy = zmask32(colimg(x->b1 ^ ky) ^ colimg(x->b2 ^ ky));
                        x->trail = V[s][zx][zy];
                        if (c < syn_nt ? x->trail : !x->trail) break;
                    }
                    if (!x->trail) f[s]++;
                    n[s]++;
                }
            }
        }
        /* true key diagnostics */
        int cons[2] = {0, 0}, weak_ok = 1;
        for (int s = 0; s < 2; s++)
            for (int c = 0; c < n[s]; c++) {
                uint32_t kx = kd[2 * s], ky = kd[2 * s + 1];
                int zx = zmask32(colimg(cl[s][c].a1 ^ kx) ^ colimg(cl[s][c].a2 ^ kx));
                int zy = zmask32(colimg(cl[s][c].b1 ^ ky) ^ colimg(cl[s][c].b2 ^ ky));
                cons[s] += V[s][zx][zy];
                if (zx == 0 || zy == 0) weak_ok = 0;
            }
        /* candidate lists (union over pairs of detected classes) and tiers by count */
        uint64_t nc[2] = {0, 0}; uint64_t *C[2] = {NULL, NULL}; int intrue[2] = {0, 0};
        int top[2] = {0, 0}; uint64_t ntop[2] = {0, 0}, nge[2] = {0, 0};
        for (int s = 0; s < 2; s++) {
            if (n[s] < 2) continue;
            C[s] = candidates(cl[s], n[s], V[s], &nc[s]);
            uint64_t tk = ((uint64_t)kd[2 * s] << 32) | kd[2 * s + 1];
            int *cc = malloc(sizeof(int) * (nc[s] + 1));
            for (uint64_t t = 0; t < nc[s]; t++) {
                if (C[s][t] == tk) intrue[s] = 1;
                uint32_t gxx = (uint32_t)(C[s][t] >> 32), gyy = (uint32_t)C[s][t]; int k = 0;
                for (int c = 0; c < n[s]; c++) {
                    int zx = zmask32(colimg(cl[s][c].a1 ^ gxx) ^ colimg(cl[s][c].a2 ^ gxx));
                    int zy = zmask32(colimg(cl[s][c].b1 ^ gyy) ^ colimg(cl[s][c].b2 ^ gyy));
                    k += V[s][zx][zy];
                }
                cc[t] = k; if (k > top[s]) top[s] = k;
            }
            for (uint64_t t = 0; t < nc[s]; t++) { if (cc[t] == top[s]) ntop[s]++; if (cc[t] >= cons[s]) nge[s]++; }
            free(cc);
        }
        double l2 = (nc[0] && nc[1]) ? log2((double)nc[0]) + log2((double)nc[1]) : -1;
        /* tiered search cost: all candidates ranked at least as high as the true key, in both structures */
        double l2t = (nge[0] && nge[1]) ? log2((double)nge[0]) + log2((double)nge[1]) : -1;
        int found = 0;
        if (nc[0] && nc[1] && l2 <= 28) {
            /* verify with one known plaintext/ciphertext pair */
            uint8_t pt[16]; for (int b = 0; b < 16; b++) pt[b] = (uint8_t)sm64();
            __m128i pv = _mm_loadu_si128((const __m128i *)pt), cv = enc5(pv, rk);
            for (uint64_t a = 0; a < nc[0] && !found; a++)
                for (uint64_t b = 0; b < nc[1]; b++) {
                    uint32_t g[4] = {(uint32_t)(C[0][a] >> 32), (uint32_t)C[0][a], (uint32_t)(C[1][b] >> 32), (uint32_t)C[1][b]};
                    uint8_t kk[16];
                    for (int d = 0; d < 4; d++) for (int r = 0; r < 4; r++) kk[diag_byte(d, r)] = (uint8_t)(g[d] >> (8 * r));
                    __m128i rr[11]; expand(kk, rr);
                    if (_mm_movemask_epi8(_mm_cmpeq_epi8(enc5(pv, rr), cv)) == 0xFFFF) { found = !memcmp(kk, mk, 16) ? 1 : 2; break; }
                }
        } else if (nc[0] && nc[1]) found = intrue[0] && intrue[1];
        free(C[0]); free(C[1]);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double secs = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
        printf("%ld,%llu,%llu,%d,%d,%d,%d,%d,%d,%llu,%llu,%d,%llu,%llu,%d,%llu,%llu,%.2f,%.2f,%d,%d,%.0f\n", at, (unsigned long long)seed,
               (unsigned long long)M, n[0], f[0], n[1], f[1], cons[0], cons[1], (unsigned long long)nc[0], (unsigned long long)nc[1],
               top[0], (unsigned long long)ntop[0], (unsigned long long)nge[0], top[1], (unsigned long long)ntop[1], (unsigned long long)nge[1],
               l2, l2t, found, weak_ok, secs);
        fflush(stdout);
    }
    return 0;
}

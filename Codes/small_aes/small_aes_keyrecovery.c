/*
 * small_aes_keyrecovery.c -- end-to-end Small-AES analogue of the 5-round key-recovery
 * attack (Algorithm 3): two structures (diagonals {0,1} and {2,3} active),
 * detect exchange classes (non-degenerate pairs, exchanged pair looked up by
 * index), and filter the key diagonals of k0 in three ways:
 *   strict : the weak test of the previously submitted version -- "at least one
 *            zero cell in each active column after round-1 MC" must hold for every
 *            detected class (not the exact pattern; not used in the paper);
 *   loo    : the same weak test, at most one failing class per structure (not used);
 *   exact2 : the exact one-round pattern (Observation 1, 14 sets J) and the
 *            key-candidate selection rule "count >= 2" (Section 4.2).
 * Classes are labelled right / not right with the real key (for reporting only).
 * The elimination approach of the paper keeps the correct key iff f1 = f2 = 0.
 *
 * Usage: small_aes_keyrecovery R M trials seed
 * Output (CSV per attack):
 *   n1,f1,n2,f2,strict_ok,log2cand_strict,loo_ok,log2cand_loo,exact2_ok,
 *   log2cand_exact2,ktrue1,ktrue2
 *   n = detected classes, f = detected classes that are not right classes,
 *   *_ok = correct key kept, log2cand = log2 of the candidate count (exact2: sum
 *   over pairs of classes and pattern pairs, i.e. an upper bound with
 *   multiplicity), ktrue = count of the correct key (number of detected classes
 *   whose exact pattern it satisfies).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

static const uint16_t T0[16] = {0xC66A,0x5BBE,0xA55F,0x844C,0x4226,0xFEE1,0xE779,0x7AAD,0x1998,0x9DD4,0xDFF2,0xBCC7,0x6335,0x2113,0x0000,0x388B};
static const uint16_t T1[16] = {0xAC66,0xE5BB,0xFA55,0xC844,0x6422,0x1FEE,0x9E77,0xD7AA,0x8199,0x49DD,0x2DFF,0x7BCC,0x5633,0x3211,0x0000,0xB388};
static const uint16_t T2[16] = {0x6AC6,0xBE5B,0x5FA5,0x4C84,0x2642,0xE1FE,0x79E7,0xAD7A,0x9819,0xD49D,0xF2DF,0xC7BC,0x3563,0x1321,0x0000,0x8B38};
static const uint16_t T3[16] = {0x66AC,0xBBE5,0x55FA,0x44C8,0x2264,0xEE1F,0x779E,0xAAD7,0x9981,0xDD49,0xFF2D,0xCC7B,0x3356,0x1132,0x0000,0x88B3};
static uint64_t sm;
static inline uint64_t rnd64(void) { uint64_t z = (sm += 0x9E3779B97F4A7C15ULL); z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL; z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL; return z ^ (z >> 31); }
#define NIB(w, r) (((w) >> (12 - 4 * (r))) & 0xF)
static inline void rnd(uint16_t c[4]) {
    uint16_t o0 = T0[NIB(c[0],0)] ^ T1[NIB(c[1],1)] ^ T2[NIB(c[2],2)] ^ T3[NIB(c[3],3)];
    uint16_t o1 = T0[NIB(c[1],0)] ^ T1[NIB(c[2],1)] ^ T2[NIB(c[3],2)] ^ T3[NIB(c[0],3)];
    uint16_t o2 = T0[NIB(c[2],0)] ^ T1[NIB(c[3],1)] ^ T2[NIB(c[0],2)] ^ T3[NIB(c[1],3)];
    uint16_t o3 = T0[NIB(c[3],0)] ^ T1[NIB(c[0],1)] ^ T2[NIB(c[1],2)] ^ T3[NIB(c[2],3)];
    c[0] = o0; c[1] = o1; c[2] = o2; c[3] = o3;
}
static inline void put_diag(uint16_t c[4], int d, uint16_t v) {
    for (int r = 0; r < 4; r++) { int col = (r + d) & 3, sh = 12 - 4 * r; c[col] = (uint16_t)((c[col] & ~(0xF << sh)) | (NIB(v, r) << sh)); }
}
static inline uint16_t get_diag(const uint16_t c[4], int d) {
    uint16_t v = 0; for (int r = 0; r < 4; r++) v |= NIB(c[(r + d) & 3], r) << (12 - 4 * r); return v;
}
static inline int zmask(uint16_t diff) { int z = 0; for (int r = 0; r < 4; r++) if (NIB(diff, r) == 0) z |= 1 << r; return z; }

/* VALID[z_x][z_y] for exchange of diagonal dy in a structure with active diagonals (dx, dy):
 * generic geometry -- computed directly with states instead of a closed form. */
static int R_, M_;
static uint16_t rk[16][4];
static uint16_t CI[4][65536];      /* CI[d][x]: column d after round 1 (key 0) for diagonal value x in diag d */

typedef struct { uint16_t a1, a2, b1, b2; int trail; } cls_t;

/* returns number of classes (one entry per class) */
static int run_structure(int dx, int dy, uint16_t (*F)[4], int32_t *head, int32_t *next, cls_t *out, int maxout) {
    int M = M_, N = M * M;
    static uint16_t A[4096], B[4096]; static uint8_t used[65536];
    uint64_t w = rnd64(); uint16_t base[4]; for (int c = 0; c < 4; c++) base[c] = (uint16_t)(w >> (16 * c));
    memset(used, 0, sizeof used); for (int i = 0; i < M; i++) { uint16_t v; do v = (uint16_t)rnd64(); while (used[v]); used[v] = 1; A[i] = v; }
    memset(used, 0, sizeof used); for (int j = 0; j < M; j++) { uint16_t v; do v = (uint16_t)rnd64(); while (used[v]); used[v] = 1; B[j] = v; }
    for (int i = 0; i < M; i++) for (int j = 0; j < M; j++) {
        uint16_t c[4]; memcpy(c, base, 8); put_diag(c, dx, A[i]); put_diag(c, dy, B[j]);
        for (int q = 0; q < 4; q++) c[q] ^= rk[0][q];
        for (int r = 1; r < R_; r++) { rnd(c); for (int q = 0; q < 4; q++) c[q] ^= rk[r][q]; }
        memcpy(F[i * M + j], c, 8);
    }
    uint16_t kx = get_diag(rk[0], dx), ky = get_diag(rk[0], dy);
    int n = 0;
    for (int k = 0; k < 4; k++) {
        memset(head, 0xFF, sizeof(int32_t) * 65536);
        for (int x = 0; x < N; x++) { uint16_t v = F[x][k]; next[x] = head[v]; head[v] = x; }
        for (int v = 0; v < 65536; v++)
            for (int x = head[v]; x >= 0; x = next[x])
                for (int y = next[x]; y >= 0; y = next[y]) {
                    int i1 = x / M, j1 = x % M, i2 = y / M, j2 = y % M;
                    if (i1 == i2 || j1 == j2) continue;
                    if (F[i1 * M + j2][k] != F[i2 * M + j1][k]) continue;
                    if (i1 > i2) { int t = i1; i1 = i2; i2 = t; t = j1; j1 = j2; j2 = t; }
                    if (j1 > j2) continue;          /* keep one representative per class */
                    if (n < maxout) {
                        cls_t *c = &out[n++];
                        c->a1 = A[i1]; c->a2 = A[i2]; c->b1 = B[j1]; c->b2 = B[j2];
                        /* trail classification with the real key: round-1 columns dx, dy must
                         * both contain a zero cell (necessary) and the exact Eq.(1) holds */
                        uint16_t s1[4], s2[4], s3[4], s4[4];
                        memcpy(s1, base, 8); put_diag(s1, dx, A[i1]); put_diag(s1, dy, B[j1]);
                        memcpy(s2, base, 8); put_diag(s2, dx, A[i2]); put_diag(s2, dy, B[j2]);
                        memcpy(s3, base, 8); put_diag(s3, dx, A[i1]); put_diag(s3, dy, B[j2]);
                        memcpy(s4, base, 8); put_diag(s4, dx, A[i2]); put_diag(s4, dy, B[j1]);
                        for (int q = 0; q < 4; q++) { s1[q] ^= rk[0][q]; s2[q] ^= rk[0][q]; s3[q] ^= rk[0][q]; s4[q] ^= rk[0][q]; }
                        rnd(s1); rnd(s2); rnd(s3); rnd(s4);
                        /* is (s3,s4) a diagonal exchange of (s1,s2) for some nontrivial mask? */
                        int ok = 0;
                        for (int mask = 1; mask <= 14 && !ok; mask++) {
                            int good = 1;
                            for (int d = 0; d < 4 && good; d++) {
                                uint16_t d1 = get_diag(s1, d), d2 = get_diag(s2, d), d3 = get_diag(s3, d), d4 = get_diag(s4, d);
                                if ((mask >> d) & 1) good = (d3 == d2 && d4 == d1); else good = (d3 == d1 && d4 == d2);
                            }
                            ok = good;
                        }
                        c->trail = ok;
                        (void)kx; (void)ky;
                    }
                }
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: small_aes_keyrecovery R M trials seed\n"); return 1; }
    R_ = atoi(argv[1]); M_ = atoi(argv[2]); long long T = atoll(argv[3]); uint64_t seed = strtoull(argv[4], NULL, 10);
    int N = M_ * M_;
    uint16_t (*F)[4] = malloc(sizeof(uint16_t[4]) * N);
    int32_t *next = malloc(sizeof(int32_t) * N), *head = malloc(sizeof(int32_t) * 65536);
    static cls_t cl[2][256];
    static uint32_t mask[4][65536];
    /* CI tables: column d after SB,SR,MC for diagonal-d value x (other cells zero, no key) */
    for (int d = 0; d < 4; d++) for (int x = 0; x < 65536; x++) { uint16_t c[4] = {0,0,0,0}; put_diag(c, d, (uint16_t)x); rnd(c); CI[d][x] = c[d]; }
    /* note: other diagonals contribute T[0] constants to column d? -- no: column d only reads diagonal d */
    for (long long t = 0; t < T; t++) {
        sm = seed * 0x100000001B3ULL ^ (uint64_t)t * 0xD6E8FEB86659FD93ULL; rnd64(); rnd64();
        for (int r = 0; r < R_; r++) { uint64_t w = rnd64(); for (int c = 0; c < 4; c++) rk[r][c] = (uint16_t)(w >> (16 * c)); }
        int dxs[2] = {0, 2}, dys[2] = {1, 3};
        int n[2], f[2];
        long double lstrict = 0, lloo = 0, lex = 0; int strict_ok = 1, loo_ok = 1, ex_ok = 1; int ntrue_ok[2];
        for (int s = 0; s < 2; s++) {
            n[s] = run_structure(dxs[s], dys[s], F, head, next, cl[s], 256);
            f[s] = 0; for (int i = 0; i < n[s]; i++) if (!cl[s][i].trail) f[s]++;
            int nn = n[s] < 32 ? n[s] : 32;
            int dd[2] = {dxs[s], dys[s]};
            for (int h = 0; h < 2; h++) {
                int d = dd[h];
                for (int g = 0; g < 65536; g++) {
                    uint32_t m = 0;
                    for (int i = 0; i < nn; i++) {
                        uint16_t x1 = h ? cl[s][i].b1 : cl[s][i].a1, x2 = h ? cl[s][i].b2 : cl[s][i].a2;
                        if (zmask(CI[d][x1 ^ g] ^ CI[d][x2 ^ g])) m |= 1u << i;
                    }
                    mask[d][g] = m;
                }
            }
            uint32_t full = nn ? ((nn == 32) ? 0xFFFFFFFFu : ((1u << nn) - 1)) : 0;
            uint16_t kx = get_diag(rk[0], dxs[s]), ky = get_diag(rk[0], dys[s]);
            /* strict */
            double ca = 0, cb = 0;
            for (int g = 0; g < 65536; g++) { if (mask[dxs[s]][g] == full) ca++; if (mask[dys[s]][g] == full) cb++; }
            if (!(mask[dxs[s]][kx] == full && mask[dys[s]][ky] == full)) strict_ok = 0;
            lstrict += log2l(ca) + log2l(cb);
            /* leave-one-out: popcount(ma & mb) >= nn-1, via mask histograms */
            if (nn <= 16) {
                static uint32_t Ha[65536], Hb[65536];
                memset(Ha, 0, sizeof(uint32_t) << nn); memset(Hb, 0, sizeof(uint32_t) << nn);
                for (int g = 0; g < 65536; g++) { Ha[mask[dxs[s]][g]]++; Hb[mask[dys[s]][g]]++; }
                long double cnt = 0;
                int thr = nn > 0 ? nn - 1 : 0;
                for (uint32_t x = 0; x < (1u << nn); x++) if (Ha[x] && __builtin_popcount(x) >= thr)
                    for (uint32_t y = 0; y < (1u << nn); y++) if (Hb[y] && __builtin_popcount(x & y) >= thr) cnt += (long double)Ha[x] * Hb[y];
                lloo += log2l(cnt);
                if (__builtin_popcount(mask[dxs[s]][kx] & mask[dys[s]][ky]) < thr) loo_ok = 0;
            } else { lloo += 0; }
            /* exact one-round pattern filter: key pair (g,h) is consistent with class c iff
             * (z_dx(g), z_dy(h)) matches the zero pattern of some nontrivial exchange mask v'.
             * Rule: keep (g,h) consistent with >= 2 classes. */
            {
                int dx = dxs[s], dy = dys[s];
                int need0[15], need1[15];
                for (int v = 1; v <= 14; v++) {
                    int z0 = 0, on1 = 0;
                    for (int d = 0; d < 4; d++) if ((v >> d) & 1) { z0 |= 1 << ((dx - d) & 3); on1 |= 1 << ((dy - d) & 3); }
                    need0[v] = z0; need1[v] = (~on1) & 0xF;
                }
                static uint64_t G[32][15][1024], H[32][15][1024];
                int nc = n[s] < 32 ? n[s] : 32;
                int true_ok = 0;
                for (int c = 0; c < nc; c++) {
                    memset(G[c], 0, sizeof G[c]); memset(H[c], 0, sizeof H[c]);
                    for (int g = 0; g < 65536; g++) {
                        int za = zmask(CI[dx][cl[s][c].a1 ^ g] ^ CI[dx][cl[s][c].a2 ^ g]);
                        int zb = zmask(CI[dy][cl[s][c].b1 ^ g] ^ CI[dy][cl[s][c].b2 ^ g]);
                        for (int v = 1; v <= 14; v++) {
                            if ((za & need0[v]) == need0[v]) G[c][v][g >> 6] |= 1ULL << (g & 63);
                            if ((zb & need1[v]) == need1[v]) H[c][v][g >> 6] |= 1ULL << (g & 63);
                        }
                    }
                    int ok = 0;
                    for (int v = 1; v <= 14; v++)
                        if (((G[c][v][kx >> 6] >> (kx & 63)) & 1) && ((H[c][v][ky >> 6] >> (ky & 63)) & 1)) ok = 1;
                    true_ok += ok;
                }
                long double cand = 0;
                for (int c1 = 0; c1 < nc; c1++) for (int c2 = c1 + 1; c2 < nc; c2++)
                    for (int v1 = 1; v1 <= 14; v1++) for (int v2 = 1; v2 <= 14; v2++) {
                        long long pg = 0, ph = 0;
                        for (int w = 0; w < 1024; w++) pg += __builtin_popcountll(G[c1][v1][w] & G[c2][v2][w]);
                        if (!pg) continue;
                        for (int w = 0; w < 1024; w++) ph += __builtin_popcountll(H[c1][v1][w] & H[c2][v2][w]);
                        cand += (long double)pg * ph;
                    }
                if (true_ok < 2) ex_ok = 0;
                lex += (cand > 0) ? log2l(cand) : -99;
                ntrue_ok[s] = true_ok;
            }
        }
        printf("%d,%d,%d,%d,%d,%.2f,%d,%.2f,%d,%.2f,%d,%d\n", n[0], f[0], n[1], f[1], strict_ok, (double)lstrict, loo_ok, (double)lloo, ex_ok, (double)lex, ntrue_ok[0], ntrue_ok[1]);
    }
    return 0;
}

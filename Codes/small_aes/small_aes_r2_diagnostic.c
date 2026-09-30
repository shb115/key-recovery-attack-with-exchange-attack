/*
 * small_aes_r2_diagnostic.c -- variant of small_aes_distinguisher.c that also records,
 * for every detected pair, the number of zero cells / zero diagonals of the
 * difference after two rounds (used to explain the small excess of non-trail
 * classes at 5 rounds). Small-AES (4-bit cells) scale model of the 5-round
 * exchange distinguisher, for measuring the full per-trial distribution
 * of the number of right pairs / equivalence classes.
 *
 * Structure: diagonals 0 and 1 active (M1 and M2 distinct random 16-bit
 * values, sampled without replacement), diagonals 2,3 fixed (random).
 * Text index = i*M2 + j.  Exchange of diagonal 1: partner of pair
 * ((i1,j1),(i2,j2)) is ((i1,j2),(i2,j1)) -- a table lookup, no re-encryption.
 * Pairs with i1==i2 or j1==j2 (equal on an active diagonal) are excluded.
 *
 * Ciphertext zero on inverse diagonal k  <=>  column k of the state after
 * (R-1) full rounds has zero difference (last half round is bijective per
 * column after SB, SR only permutes), so we store those columns.
 *
 * For each detected right pair we also check the exact one-round exchange
 * condition (Eq.(1)) to split "trail" classes from "random" classes, and we
 * compute M = number of classes in the structure satisfying Eq.(1)
 * (via zero-mask histograms of column-0 / column-1 differences), which
 * gives the per-trial conditional mean lambda_t = M*q + (Ntot-M)*q*2^-16.
 *
 * Usage: small_aes_r2_diagnostic R M1 M2 trials seed keymode [out.csv] [dump_thr]
 * (diagnostic used during the revision; no results of it are reported in the paper)
 *   keymode 0: independent random round keys; 1: same key every round.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static const uint16_t T0[16] = {0xC66A,0x5BBE,0xA55F,0x844C,0x4226,0xFEE1,0xE779,0x7AAD,0x1998,0x9DD4,0xDFF2,0xBCC7,0x6335,0x2113,0x0000,0x388B};
static const uint16_t T1[16] = {0xAC66,0xE5BB,0xFA55,0xC844,0x6422,0x1FEE,0x9E77,0xD7AA,0x8199,0x49DD,0x2DFF,0x7BCC,0x5633,0x3211,0x0000,0xB388};
static const uint16_t T2[16] = {0x6AC6,0xBE5B,0x5FA5,0x4C84,0x2642,0xE1FE,0x79E7,0xAD7A,0x9819,0xD49D,0xF2DF,0xC7BC,0x3563,0x1321,0x0000,0x8B38};
static const uint16_t T3[16] = {0x66AC,0xBBE5,0x55FA,0x44C8,0x2264,0xEE1F,0x779E,0xAAD7,0x9981,0xDD49,0xFF2D,0xCC7B,0x3356,0x1132,0x0000,0x88B3};

static uint64_t sm_state;
static inline uint64_t splitmix64(void) {
    uint64_t z = (sm_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

#define NIB(w, r) (((w) >> (12 - 4 * (r))) & 0xF)

/* one full round (SB,SR,MC) on column words, no key */
static inline void rnd(uint16_t c[4]) {
    uint16_t o0 = T0[NIB(c[0],0)] ^ T1[NIB(c[1],1)] ^ T2[NIB(c[2],2)] ^ T3[NIB(c[3],3)];
    uint16_t o1 = T0[NIB(c[1],0)] ^ T1[NIB(c[2],1)] ^ T2[NIB(c[3],2)] ^ T3[NIB(c[0],3)];
    uint16_t o2 = T0[NIB(c[2],0)] ^ T1[NIB(c[3],1)] ^ T2[NIB(c[0],2)] ^ T3[NIB(c[1],3)];
    uint16_t o3 = T0[NIB(c[3],0)] ^ T1[NIB(c[0],1)] ^ T2[NIB(c[1],2)] ^ T3[NIB(c[2],3)];
    c[0] = o0; c[1] = o1; c[2] = o2; c[3] = o3;
}

/* put 16-bit diagonal value v (row r nibble = NIB(v,r)) into diagonal d */
static inline void put_diag(uint16_t c[4], int d, uint16_t v) {
    for (int r = 0; r < 4; r++) {
        int col = (r + d) & 3;
        int sh = 12 - 4 * r;
        c[col] = (uint16_t)((c[col] & ~(0xF << sh)) | (NIB(v, r) << sh));
    }
}

static int VALID[16][16]; /* VALID[z0][z1]: Eq.(1) holds for some v' */

static void init_valid(void) {
    for (int z0 = 0; z0 < 16; z0++)
        for (int z1 = 0; z1 < 16; z1++) {
            int ok = 0;
            for (int v = 1; v <= 14; v++) {
                int need0 = 0, on1 = 0;
                for (int d = 0; d < 4; d++)
                    if ((v >> d) & 1) { need0 |= 1 << ((4 - d) & 3); on1 |= 1 << ((1 - d) & 3); }
                int need1 = (~on1) & 0xF;
                if ((z0 & need0) == need0 && (z1 & need1) == need1) { ok = 1; break; }
            }
            VALID[z0][z1] = ok;
        }
}

static inline int zmask(uint16_t diff) {
    int z = 0;
    for (int r = 0; r < 4; r++) if (NIB(diff, r) == 0) z |= 1 << r;
    return z;
}

int main(int argc, char **argv) {
    if (argc < 7) { fprintf(stderr, "usage: small_aes_r2_diagnostic R M1 M2 trials seed keymode [out.csv]\n"); return 1; }
    int R = atoi(argv[1]);
    int M1 = atoi(argv[2]), M2 = atoi(argv[3]);
    long long trials = atoll(argv[4]);
    uint64_t seed = strtoull(argv[5], NULL, 10);
    int keymode = atoi(argv[6]);
    FILE *out = (argc > 7 && strcmp(argv[7], "-")) ? fopen(argv[7], "w") : NULL;
    int dump_thr = (argc > 8) ? atoi(argv[8]) : 1 << 30;
    static int rec[1 << 16][6]; int nrec = 0;
    int N = M1 * M2;

    init_valid();
    uint16_t (*F)[4] = malloc(sizeof(uint16_t[4]) * N);
    int32_t *next = malloc(sizeof(int32_t) * N);
    int32_t *head = malloc(sizeof(int32_t) * 65536);
    uint16_t *A = malloc(2 * M1), *B = malloc(2 * M2);
    uint16_t *XA = malloc(2 * M1), *XB = malloc(2 * M2); /* round-1 col0 / col1 */
    uint8_t *used = malloc(65536);
    long long hist[4096] = {0};
    long long parity_viol = 0; long long zdiag_nt[5]={0}, zdiag_t[5]={0}, zcell_nt[17]={0};
    double sum_c = 0, sum_c2 = 0;

    for (long long t = 0; t < trials; t++) {
        sm_state = seed * 0x100000001B3ULL ^ (uint64_t)t * 0xD6E8FEB86659FD93ULL;
        splitmix64(); splitmix64();
        uint16_t rk[16][4];
        uint64_t w = splitmix64();
        for (int r = 0; r < R; r++) {
            if (keymode == 1 && r > 0) { memcpy(rk[r], rk[0], 8); continue; }
            w = splitmix64();
            for (int c = 0; c < 4; c++) rk[r][c] = (uint16_t)(w >> (16 * c));
        }
        w = splitmix64();
        uint16_t base[4];
        for (int c = 0; c < 4; c++) base[c] = (uint16_t)(w >> (16 * c));
        memset(used, 0, 65536);
        for (int i = 0; i < M1; i++) { uint16_t v; do v = (uint16_t)splitmix64(); while (used[v]); used[v] = 1; A[i] = v; }
        memset(used, 0, 65536);
        for (int j = 0; j < M2; j++) { uint16_t v; do v = (uint16_t)splitmix64(); while (used[v]); used[v] = 1; B[j] = v; }

        /* round-1 images of the active columns (key-dependent, diff-only) */
        for (int i = 0; i < M1; i++) {
            uint16_t c[4]; memcpy(c, base, 8); put_diag(c, 0, A[i]);
            for (int q = 0; q < 4; q++) c[q] ^= rk[0][q];
            rnd(c); XA[i] = c[0];
        }
        for (int j = 0; j < M2; j++) {
            uint16_t c[4]; memcpy(c, base, 8); put_diag(c, 1, B[j]);
            for (int q = 0; q < 4; q++) c[q] ^= rk[0][q];
            rnd(c); XB[j] = c[1];
        }
        /* M: number of classes (a-pair, b-pair) satisfying Eq.(1) */
        long long Ha[16] = {0}, Hb[16] = {0};
        for (int i1 = 0; i1 < M1; i1++) for (int i2 = i1 + 1; i2 < M1; i2++) Ha[zmask(XA[i1] ^ XA[i2])]++;
        for (int j1 = 0; j1 < M2; j1++) for (int j2 = j1 + 1; j2 < M2; j2++) Hb[zmask(XB[j1] ^ XB[j2])]++;
        long long Mcls = 0;
        for (int a = 0; a < 16; a++) for (int b = 0; b < 16; b++) if (VALID[a][b]) Mcls += Ha[a] * Hb[b];

        /* encrypt the structure: AK0 + (R-1) full rounds (+AK) */
        for (int i = 0; i < M1; i++)
            for (int j = 0; j < M2; j++) {
                uint16_t c[4]; memcpy(c, base, 8);
                put_diag(c, 0, A[i]); put_diag(c, 1, B[j]);
                for (int q = 0; q < 4; q++) c[q] ^= rk[0][q];
                for (int r = 1; r < R; r++) { rnd(c); for (int q = 0; q < 4; q++) c[q] ^= rk[r][q]; }
                memcpy(F[i * M2 + j], c, 8);
            }

        long long pairs = 0, trailpairs = 0; nrec = 0;
        for (int k = 0; k < 4; k++) {
            memset(head, 0xFF, sizeof(int32_t) * 65536);
            for (int x = 0; x < N; x++) { uint16_t v = F[x][k]; next[x] = head[v]; head[v] = x; }
            for (int v = 0; v < 65536; v++)
                for (int x = head[v]; x >= 0; x = next[x])
                    for (int y = next[x]; y >= 0; y = next[y]) {
                        int i1 = x / M2, j1 = x % M2, i2 = y / M2, j2 = y % M2;
                        if (i1 == i2 || j1 == j2) continue;
                        if (F[i1 * M2 + j2][k] == F[i2 * M2 + j1][k]) {
                            pairs++;
                            int tr = VALID[zmask(XA[i1] ^ XA[i2])][zmask(XB[j1] ^ XB[j2])];
                            {   /* R^2 difference (two full rounds incl. keys) of the detected pair */
                                uint16_t s1[4], s2[4]; memcpy(s1, base, 8); memcpy(s2, base, 8);
                                put_diag(s1, 0, A[i1]); put_diag(s1, 1, B[j1]); put_diag(s2, 0, A[i2]); put_diag(s2, 1, B[j2]);
                                for (int rr = 0; rr < 2; rr++) { for (int q2 = 0; q2 < 4; q2++) { s1[q2] ^= rk[rr][q2]; s2[q2] ^= rk[rr][q2]; } rnd(s1); rnd(s2); }
                                int zc = 0, zd = 0;
                                for (int d = 0; d < 4; d++) { int all = 1; for (int r = 0; r < 4; r++) { int col = (r + d) & 3; if (NIB(s1[col] ^ s2[col], r)) all = 0; else zc++; } zd += all; }
                                if (tr) zdiag_t[zd]++; else { zdiag_nt[zd]++; zcell_nt[zc]++; }
                            }
                            if (tr) trailpairs++;
                            if (nrec < (1 << 16)) { rec[nrec][0]=i1; rec[nrec][1]=j1; rec[nrec][2]=i2; rec[nrec][3]=j2; rec[nrec][4]=k; rec[nrec][5]=tr; nrec++; }
                        }
                    }
        }
        if (pairs & 1) parity_viol++;
        if (pairs / 2 >= dump_thr) {
            printf("TRIAL %lld cls=%lld trail=%lld M=%lld\n", t, pairs / 2, trailpairs / 2, Mcls);
            for (int q = 0; q < nrec; q++)
                printf("  (%d,%d)-(%d,%d) k=%d trail=%d z0=%x z1=%x\n", rec[q][0], rec[q][1], rec[q][2], rec[q][3], rec[q][4], rec[q][5],
                       zmask(XA[rec[q][0]] ^ XA[rec[q][2]]), zmask(XB[rec[q][1]] ^ XB[rec[q][3]]));
        }
        long long cls = pairs / 2;
        if (cls < 4096) hist[cls]++;
        sum_c += cls; sum_c2 += (double)cls * cls;
        if (out) fprintf(out, "%lld,%lld,%lld\n", cls, trailpairs / 2, Mcls);
    }
    double m = sum_c / trials, var = sum_c2 / trials - m * m;
    printf("R=%d M1=%d M2=%d trials=%lld seed=%llu keymode=%d\n", R, M1, M2, trials, (unsigned long long)seed, keymode);
    printf("mean_classes=%.5f var=%.5f D=%.4f parity_viol=%lld\n", m, var, var / m, parity_viol);
    printf("hist:");
    for (int c = 0; c < 4096; c++) if (hist[c]) printf(" %d:%lld", c, hist[c]);
    printf("\n");
    printf("zero-diagonals of R^2 diff, non-trail detected:"); for (int q = 0; q < 5; q++) printf(" %d:%lld", q, zdiag_nt[q]); printf("\n");
    printf("zero-diagonals of R^2 diff, trail detected:"); for (int q = 0; q < 5; q++) printf(" %d:%lld", q, zdiag_t[q]); printf("\n");
    printf("zero-cells of R^2 diff, non-trail detected:"); for (int q = 0; q < 17; q++) printf(" %d:%lld", q, zcell_nt[q]); printf("\n");
    if (out) fclose(out);
    return 0;
}

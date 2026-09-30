"""Exact lambda_S of random full-AES structures (Section 3.2 of the paper) without encryption.

lambda_S = N_rc * q + N_c * 2^-62, where N_rc (M in the code) = number of classes of the 2^30
structure whose pairs satisfy the one-round condition Eq.(1) (depends only on the two diagonal
value sets and k0), q = P[ciphertext zero on some inverse diagonal] ~ 4*2^-32, and
N_c * 2^-62 = 0.0625.

N_rc is computed exactly from 'agree-on-row-set' pair counts + Moebius inversion, so no 2^29
pair loop is needed.  Usage: python3 lambda_structure.py good|glibc|msvc T seed [m];
output per structure: trial,N_rc,lambda_S,dupA,dupB.  Results/aes/lambda_structure/FL_good.csv
was produced by "python3 lambda_structure.py good 2000 7".  RNG modes:
  good : splitmix-like numpy PCG64 (distinct values)
  msvc : exact emulation of MinGW/MSVCRT rand() consumption in legacy/exchange_distinguisher_v1.c
  glibc: emulation of glibc TYPE_3 rand()
"""
import sys, numpy as np

SBOX = np.array([
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16],dtype=np.uint8)

def xt(x):
    x = x.astype(np.uint16) << 1
    return (np.where(x & 0x100, x ^ 0x11B, x) & 0xFF).astype(np.uint8)

def mc_col(s0, s1, s2, s3):
    t = s0 ^ s1 ^ s2 ^ s3
    return (s0 ^ t ^ xt(s0 ^ s1), s1 ^ t ^ xt(s1 ^ s2), s2 ^ t ^ xt(s2 ^ s3), s3 ^ t ^ xt(s3 ^ s0))

# rows of the active column after round 1 come from these plaintext byte positions
DIAG0_ROWS = [0, 5, 10, 15]      # col 0: rows 0..3
DIAG1_ROWS = [4, 9, 14, 3]       # col 1: rows 0..3
IDX1 = [0, 5, 10, 15]            # in_active_indexes1 (rand_diag0[b] -> byte IDX1[b])
IDX2 = [3, 4, 9, 14]             # in_active_indexes2 (rand_diag1[b] -> byte IDX2[b])

def valid_table():
    V = np.zeros((16, 16), bool)
    for z0 in range(16):
        for z1 in range(16):
            for v in range(1, 15):
                need0 = on1 = 0
                for d in range(4):
                    if v >> d & 1:
                        need0 |= 1 << ((4 - d) & 3); on1 |= 1 << ((1 - d) & 3)
                need1 = (~on1) & 15
                if z0 & need0 == need0 and z1 & need1 == need1:
                    V[z0, z1] = True; break
    return V
VALID = valid_table()

def zero_mask_hist(col):
    """col: (m,4) uint8 array of distinct-ish column images. Returns H[z] = #pairs whose
    difference has zero-mask exactly z (bit r = row r zero)."""
    m = col.shape[0]
    key = col.astype(np.uint32)
    N = np.zeros(16)  # N[R] = #pairs agreeing on (at least) rows R
    for R in range(16):
        if R == 0:
            N[R] = m * (m - 1) / 2; continue
        k = np.zeros(m, np.uint64)
        for r in range(4):
            if R >> r & 1:
                k = (k << np.uint64(8)) | key[:, r].astype(np.uint64)
        _, cnt = np.unique(k, return_counts=True)
        N[R] = (cnt * (cnt - 1) / 2).sum()
    # Moebius: H[z] = sum_{R superset of z} (-1)^{|R|-|z|} N[R]
    H = np.zeros(16)
    for z in range(16):
        for R in range(16):
            if R & z == z:
                H[z] += (-1) ** (bin(R).count('1') - bin(z).count('1')) * N[R]
    return H

class MSVC:
    def __init__(self, seed): self.s = seed & 0xFFFFFFFF
    def rand(self):
        self.s = (self.s * 214013 + 2531011) & 0xFFFFFFFF
        return (self.s >> 16) & 0x7FFF
    def bytes_block(self, n):  # n successive rand() & 0xFF, vectorised via LCG jump
        out = np.empty(n, np.uint8)
        for i in range(n):
            out[i] = self.rand() & 0xFF
        return out

class GLIBC:
    def __init__(self, seed):
        r = [0] * 344
        r[0] = seed if seed else 1
        for i in range(1, 31):
            hi, lo = divmod(r[i - 1], 127773)
            word = 16807 * lo - 2836 * hi
            if word < 0: word += 2147483647
            r[i] = word
        for i in range(31, 34): r[i] = r[i - 31]
        for i in range(34, 344): r[i] = (r[i - 31] + r[i - 3]) & 0xFFFFFFFF
        self.r = r
    def rand(self):
        v = (self.r[-31] + self.r[-3]) & 0xFFFFFFFF
        self.r.append(v); self.r.pop(0)
        return v >> 1
    def bytes_block(self, n):
        return np.array([self.rand() & 0xFF for _ in range(n)], np.uint8)

def trial_sets(mode, gen, m):
    if mode == 'good':
        mk = gen.integers(0, 256, 16, dtype=np.uint8)
        A = gen.integers(0, 256, (m, 4), dtype=np.uint8)
        B = gen.integers(0, 256, (m, 4), dtype=np.uint8)
    else:
        kp = gen.bytes_block(32)
        mk = kp[0::2].copy()       # mk[i] = rand()%256; pt[i] = rand()%256 interleaved
        A = gen.bytes_block(4 * m).reshape(m, 4)
        B = gen.bytes_block(4 * m).reshape(m, 4)
    return mk, A, B

def lam(mk, A, B, m):
    pa = np.zeros((m, 16), np.uint8); pb = np.zeros((m, 16), np.uint8)
    for b in range(4):
        pa[:, IDX1[b]] = A[:, b]; pb[:, IDX2[b]] = B[:, b]
    ca = mc_col(*[SBOX[pa[:, p] ^ mk[p]] for p in DIAG0_ROWS])
    cb = mc_col(*[SBOX[pb[:, p] ^ mk[p]] for p in DIAG1_ROWS])
    Ha = zero_mask_hist(np.stack(ca, 1)); Hb = zero_mask_hist(np.stack(cb, 1))
    Ha[15] = 0; Hb[15] = 0   # identical diagonal values (duplicates) are excluded pairs
    M = (Ha[:, None] * Hb[None, :] * VALID).sum()
    q = 1 - (1 - 2.0 ** -32) ** 4
    ncls = (m * (m - 1) / 2) ** 2
    return M, M * q + ncls * 2.0 ** -62

if __name__ == '__main__':
    mode = sys.argv[1]; T = int(sys.argv[2]); seed = int(sys.argv[3]); m = int(sys.argv[4]) if len(sys.argv) > 4 else 1 << 15
    gen = {'good': lambda s: np.random.default_rng(s), 'msvc': MSVC, 'glibc': GLIBC}[mode](seed)
    for t in range(T):
        mk, A, B = trial_sets(mode, gen, m)
        M, l = lam(mk, A, B, m)
        dupA = m - len(np.unique(A.view(np.uint32))); dupB = m - len(np.unique(B.view(np.uint32)))
        print(f'{t},{M:.0f},{l:.5f},{dupA},{dupB}', flush=True)

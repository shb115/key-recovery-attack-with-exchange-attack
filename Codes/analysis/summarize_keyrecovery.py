"""Summary statistics of the key-recovery experiments reported in Sections 4.3 and 4.4.

Usage (from the repository root):
    python3 Codes/analysis/summarize_keyrecovery.py

Prints, for the Small-AES attacks (Results/small_aes/keyrecovery/KX181_all.csv) and for the
two full-AES sets (Results/aes/keyrecovery/e7_*.csv with M = 44720 and e4_*, e5_*, e6_*.csv
with M = 49312): right classes and other detected classes per structure, the number of attacks
in which the count of the correct key differs from the number of right classes (expected 0),
the success rate of the count rule and its prediction, the check that the failures are exactly
the attacks with fewer than two right classes in a structure, the survival and success rates of
the elimination approach, and the size of the final search; and, for the 6-round filtering
(Results/aes/keyrecovery_6r_filter/kr6f.csv), the wrong-key pass rate and the candidates left
by two right classes.  Requires numpy only.
"""
import glob
import math
import os

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'Results')
P5_12 = 2.0 ** -28.21            # exact P*_5(1,2) for 8-bit cells, rounded as in the paper
P5_12_SMALL = 2.0 ** -12.40      # exact P*_5(1,2) for 4-bit cells, rounded as in the paper


def load(pattern, ncol):
    rows = []
    for f in sorted(glob.glob(pattern)):
        for line in open(f):
            p = line.strip().split(',')
            if len(p) == ncol:
                rows.append([float(x) for x in p])
    return np.array(rows)


def succ5(lam):
    return (1 - math.exp(-lam) * (1 + lam)) ** 2


def report(name, r0, f0, r1, f1, cons0, cons1, found, lamT, lamF, l2tiered=None, elim_ok=None):
    n = len(r0)
    print(f'==== {name}: {n} attacks')
    print(f'right classes per structure: {np.concatenate([r0, r1]).mean():.2f} (predicted {lamT:.2f}); '
          f'other detected classes: {np.concatenate([f0, f1]).mean():.2f} (predicted {lamF:.2f})')
    print(f'attacks in which count(correct key) != #right classes: {int(((cons0 != r0) | (cons1 != r1)).sum())}')
    print(f'key recovered: {int(found.sum())} ({100 * found.mean():.1f}%), predicted {100 * succ5(lamT):.1f}%')
    lt2 = np.minimum(r0, r1) < 2
    print(f'failures == attacks with <2 right classes in a structure: {np.array_equal(lt2, ~found)} '
          f'({int(lt2.sum())} attacks)')
    surv = (f0 == 0) & (f1 == 0)
    print(f'elimination approach: correct key survives (no other detected class in either structure) in '
          f'{100 * surv.mean():.1f}% (predicted e^-2lamF = {100 * math.exp(-2 * lamF):.1f}%), '
          f'succeeds in {100 * (surv & found).mean():.1f}%')
    if l2tiered is not None:
        t = l2tiered[found]
        print(f'final search (successful attacks): candidates examined, log2: median {np.median(t):.1f}, '
              f'99th percentile {np.percentile(t, 99):.1f}, max {t.max():.2f}, log2(mean) {math.log2((2.0 ** t).mean()):.2f}')


# ---- Small-AES, 181 values per diagonal
d = load(os.path.join(ROOT, 'small_aes', 'keyrecovery', 'KX181_all.csv'), 12)
if d.size:
    M = 181
    Nc = (M * (M - 1) // 2) ** 2
    report('Small-AES (M = 181)', d[:, 0] - d[:, 1], d[:, 1], d[:, 2] - d[:, 3], d[:, 3], d[:, 10], d[:, 11],
           d[:, 8] == 1, Nc * P5_12_SMALL * 2 ** -14, Nc * 2 ** -30)

# ---- full AES
for name, pat, M in (('full AES, M = 44720 (D = 2^30.90)', 'e7_*.csv', 44720),
                     ('full AES, M = 49312 (D = 2^31.18)', 'e[456]_*.csv', 49312)):
    d = load(os.path.join(ROOT, 'aes', 'keyrecovery', pat), 22)
    if not d.size:
        continue
    Nc = M ** 4 / 4
    ntop = np.concatenate([d[:, 12], d[:, 15]])
    report(name, d[:, 3] - d[:, 4], d[:, 4], d[:, 5] - d[:, 6], d[:, 6], d[:, 7], d[:, 8], d[:, 19] == 1,
           Nc * P5_12 * 2 ** -30, Nc * 2 ** -62, l2tiered=d[:, 18])
    print(f'largest number of candidates sharing the top count in a structure: 2^{math.log2(ntop.max()):.2f}')

# ---- 6-round filtering
d = load(os.path.join(ROOT, 'aes', 'keyrecovery_6r_filter', 'kr6f.csv'), 9)
if d.size:
    print(f'==== 6-round key filtering: {len(d)} keys')
    print(f'correct key satisfies both right classes in all trials: {bool((d[:, 2] == 1).all())}; '
          f'wrong-guess pass rate (geometric mean over trials of the per-class rate): 2^{d[:, 5].mean():.2f} '
          f'(predicted 2^-38.00); candidates left by two right classes: median 2^{np.median(d[:, 6]):.1f}, '
          f'max 2^{d[:, 6].max():.1f}; correct key among them in all trials: {bool((d[:, 7] == 1).all())}')

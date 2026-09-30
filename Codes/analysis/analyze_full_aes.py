"""Analysis of the full-AES distinguisher runs (Table 3 of the paper).

CSV columns: trial,mode,seed,pairs,classes,right_classes,N_rc,lambda_S,dupA,dupB,deg_collide,parity_ok,secs
(the code names right_classes and N_rc 'trail_classes' and 'M_S').
Usage: python3 analyze_full_aes.py "Results/aes/distribution/s1_m*.csv"
Prints the histogram against the mixed Poisson prediction (lambda_S of each trial) and against a single
Poisson distribution with the observed mean, with the chi-square goodness-of-fit tests of Table 3.
"""
import sys, glob
import numpy as np
from scipy import stats


def load(pattern):
    rows = []
    for f in sorted(glob.glob(pattern)):
        for line in open(f):
            p = line.strip().split(',')
            if len(p) == 13:
                rows.append([float(x) for x in p])
    return np.array(rows)


def report(pattern):
    d = load(pattern)
    if d.size == 0:
        print('no data for', pattern); return
    n = len(d)
    x = d[:, 4].astype(int); tr = d[:, 5].astype(int); lam = d[:, 7]
    print(f'==== {pattern}: n = {n} trials, parity ok = {int(d[:, 11].sum())}/{n}, '
          f'mean sec/trial = {d[:, 12].mean():.0f}')
    m, v = x.mean(), x.var(ddof=1)
    Dst = ((x - m) ** 2).sum() / m
    p_disp = stats.chi2.sf(Dst, n - 1)
    print(f'classes: mean {m:.4f} (SE {np.sqrt(v / n):.4f}), var {v:.4f}, VMR {v / m:.3f} '
          f'(dispersion test p = {p_disp:.3g}; SE(VMR) ~ {np.sqrt(2 / n):.3f})')
    print(f'lambda_S: mean {lam.mean():.4f}, sd {lam.std():.4f} -> predicted mean {lam.mean():.4f}, '
          f'predicted VMR {1 + lam.var() / lam.mean():.4f}')
    # mean test with known lambda_t
    z_mean = (x.sum() - lam.sum()) / np.sqrt(lam.sum())
    # conditional-Poisson dispersion test with known lambda_t (no fitted parameter)
    T = ((x - lam) ** 2 / lam).sum()
    z_T = (T - n) / np.sqrt((2 + 1 / lam).sum())
    print(f'known-lambda tests: mean z = {z_mean:+.2f};  sum (x-l)^2/l = {T:.1f} vs n = {n}, z = {z_T:+.2f}')
    # histogram vs mixed Poisson prediction
    kmax = max(x.max(), 8)
    obs = np.bincount(x, minlength=kmax + 1)
    exp = np.array([stats.poisson.pmf(k, lam).sum() for k in range(kmax + 1)])
    exp[-1] += stats.poisson.sf(kmax, lam).sum()
    poi = stats.poisson.pmf(np.arange(kmax + 1), m) * n
    poi[-1] += stats.poisson.sf(kmax, m) * n
    print(' k   obs    exp(mixed Poisson)  exp(Poisson, observed mean)')
    for k in range(kmax + 1):
        print(f'{k:2d} {obs[k]:6d} {exp[k]:10.2f} {poi[k]:14.2f}')
    # pooled chi-square (expected >= 5)
    o_, e_, ao, ae = [], [], 0, 0
    for k in range(kmax + 1):
        ao += obs[k]; ae += exp[k]
        if ae >= 5:
            o_.append(ao); e_.append(ae); ao = ae = 0
    if ae > 0:
        o_[-1] += ao; e_[-1] += ae
    chi = sum((a - b) ** 2 / b for a, b in zip(o_, e_))
    print(f'GoF vs mixed Poisson (no fitted params): chi2 = {chi:.2f}, df = {len(o_) - 1}, '
          f'p = {stats.chi2.sf(chi, len(o_) - 1):.3g}')
    o_, e_, ao, ae = [], [], 0, 0
    for k in range(kmax + 1):
        ao += obs[k]; ae += poi[k]
        if ae >= 5:
            o_.append(ao); e_.append(ae); ao = ae = 0
    if ae > 0:
        o_[-1] += ao; e_[-1] += ae
    chi = sum((a - b) ** 2 / b for a, b in zip(o_, e_))
    print(f'GoF vs Poisson (observed mean):          chi2 = {chi:.2f}, df = {len(o_) - 2}, '
          f'p = {stats.chi2.sf(chi, len(o_) - 2):.3g}')
    tail = (x >= 6).sum(); etail = stats.poisson.sf(5, lam).sum()
    print(f'tail: trials with >=6 classes: obs {tail}, exp {etail:.2f}')
    s = (x > 0).mean(); ps = 1 - np.exp(-lam).mean()
    lo, hi = stats.binomtest(int((x > 0).sum()), n).proportion_ci()
    print(f'success P(>=1 class): obs {s:.4f} [{lo:.4f}, {hi:.4f}], predicted {ps:.4f}')
    print(f'trail classes: {tr.sum()} / {x.sum()} ({tr.sum() / max(x.sum(), 1):.3f}); '
          f'non-trail per trial {(x - tr).mean():.4f} (random-model 0.0625)')
    print(f'dup value pairs per trial: A {d[:, 8].mean():.3f}, B {d[:, 9].mean():.3f}')


for pat in sys.argv[1:]:
    report(pat)

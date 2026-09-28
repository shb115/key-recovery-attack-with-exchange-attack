"""Analysis of the Small-Scale AES distinguisher runs (small_aes_distinguisher).

CSV columns per trial: classes, trail_classes, M  (M = #classes of the structure
satisfying the one-round exchange condition, Eq. (1) of the paper).

Usage:
    python3 analyze_small_aes.py <label>=<glob> [<label>=<glob> ...]
    e.g. python3 analyze_small_aes.py A='../../Results/small_aes/distribution/A_all.csv'

For each data set it prints the histogram, mean, variance, index of dispersion,
the chi-square test against a single Poisson distribution (fitted mean) and
against the mixed Poisson distribution given by the per-trial value
lambda_S = M * q + lambda_rand (q = 2^-14, lambda_rand = measured non-trail rate),
and the conditional analysis of the trail classes given M (quintiles).
"""
import glob
import sys

import numpy as np
from scipy import stats


def load(pattern):
    arr = [np.loadtxt(f, delimiter=',', dtype=np.int64, ndmin=2) for f in sorted(glob.glob(pattern))]
    arr = [a for a in arr if a.size]
    return np.vstack(arr) if arr else None


def pooled_chi2(obs, exp, nfit):
    o, e, ao, ae = [], [], 0.0, 0.0
    for k in range(len(obs)):
        ao += obs[k]; ae += exp[k]
        if ae >= 5 and exp[k + 1:].sum() >= 5:
            o.append(ao); e.append(ae); ao = ae = 0.0
    o[-1] += ao; e[-1] += ae
    chi = sum((a - b) ** 2 / b for a, b in zip(o, e))
    dof = len(o) - 1 - nfit
    return chi, dof, stats.chi2.sf(chi, dof)


def report(label, d, q=2.0 ** -14):
    c, t, M = d[:, 0], d[:, 1], d[:, 2]
    n = len(c); m = c.mean(); v = c.var(ddof=1)
    print(f'==== {label}: n = {n}, mean = {m:.5f}, var = {v:.5f}, index of dispersion = {v / m:.4f}')
    kmax = int(c.max())
    obs = np.bincount(c, minlength=kmax + 1).astype(float)
    lam_rand = (c - t).mean()
    lam_t = M * q + lam_rand
    mix = np.array([stats.poisson.pmf(k, lam_t).sum() for k in range(kmax + 1)])
    mix[-1] += stats.poisson.sf(kmax, lam_t).sum()
    poi = stats.poisson.pmf(np.arange(kmax + 1), m) * n
    poi[-1] += stats.poisson.sf(kmax, m) * n
    print(' k   observed   mixed_Poisson   Poisson(fitted)')
    for k in range(kmax + 1):
        print(f'{k:2d} {obs[k]:10.0f} {mix[k]:15.1f} {poi[k]:17.1f}')
    chi_m, dof_m, p_m = pooled_chi2(obs, mix, 0)
    chi_p, dof_p, p_p = pooled_chi2(obs, poi, 1)
    print(f'chi2 vs mixed Poisson (no fitted parameter): {chi_m:.2f} (df {dof_m}, p = {p_m:.3g})')
    print(f'chi2 vs Poisson (fitted mean):               {chi_p:.2f} (df {dof_p}, p = {p_p:.3g})')
    print(f'predicted mean {lam_t.mean():.5f}, predicted index of dispersion {1 + lam_t.var() / lam_t.mean():.4f}')
    print(f'success P(>=1): observed {np.mean(c > 0):.4f}, predicted {1 - np.exp(-lam_t).mean():.4f}')
    if t.sum():
        print(f'measured q = {t.sum() / M.sum():.4e} (2^{np.log2(t.sum() / M.sum()):.3f}); '
              f'non-trail classes per trial = {lam_rand:.5f}')
        qs = np.quantile(M, np.linspace(0, 1, 6))
        for a, b in zip(qs[:-1], qs[1:]):
            sel = (M >= a) & (M <= b)
            tt = t[sel]
            print(f'  M in [{a:.0f}, {b:.0f}]: n = {sel.sum()}, trail mean = {tt.mean():.4f}, '
                  f'predicted = {M[sel].mean() * q:.4f}, index of dispersion = {tt.var(ddof=1) / tt.mean():.4f}')


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        label, _, pattern = arg.partition('=')
        data = load(pattern or label)
        if data is None:
            print('no data for', arg)
        else:
            report(label, data)

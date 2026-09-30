# Revisiting Exchange Distinguisher and Key-Recovery Attacks on Reduced-Round AES

Code, raw results, and random seeds for the experiments of the paper

**"Revisiting Exchange Distinguisher and Key-Recovery Attacks on Reduced-Round AES"**
Hanbeom Shin, Byoungjin Seok, Dongjae Lee, Deukjo Hong, Jaechul Sung, Seokhie Hong.

## Overview

1. **Distribution of the number of detected classes** of the 5-round exchange distinguisher
   (Section 3). Detected pairs occur in classes of size two (Theorem 2), and the number of
   detected classes of a structure `S` is modeled as `Pois(lambda_S)` with
   `lambda_S = N_rc * q + (N_c - N_rc) * 2^-62`, where `N_c` is the number of classes of the
   structure and `N_rc` the number of classes whose pairs satisfy the one-round exchange
   condition (Eq. (1)). The model is tested on Small-AES (4-bit cells) with 10^6 trials
   (Table 2) and on full AES with 1,020 trials (Table 3).
2. **Key recovery without key-guessing rounds** (Section 4). A key guess is given the *count*
   of detected classes whose first-round difference satisfies the exact zero-byte pattern of
   Observation 1; the candidates are the guesses with count at least two, ranked by count.
   The 5-round attack is run end to end on Small-AES (10,200 attacks) and on full AES
   (920 attacks), and the 6-round key filtering (Observation 2) is verified with synthetic
   right classes.

## Repository structure

```
Codes/
  aes/                          full AES (AES-NI)
    exchange_distinguisher.c    5-round distinguisher, 2^(2L) texts per trial; per-trial
                                class counts, right/other labels, exact N_rc and lambda_S
    exchange_keyrecovery.c      end-to-end 5-round key recovery (two structures): exact
                                pattern filter, counts, ranked candidates, key verification
    exchange_keyrecovery_6r_filter.c  6-round key filtering (Observation 2) on synthetic
                                right classes: wrong-key pass rate, candidates left by two classes
    lambda_structure.py         exact lambda_S of random full-AES structures without encryption
    legacy/                     code of the previously submitted version (for reference only)
  small_aes/                    Small-AES with 4-bit cells
    small_aes_distinguisher.c   5-round distinguisher (class counts, right labels, N_rc)
    small_aes_keyrecovery.c     end-to-end key recovery (elimination approach vs. count rule)
    small_aes_p5.c              direct measurement of the one-round probability P_5(1,k)
    small_aes_r2_diagnostic.c   zero cells of the 2-round difference of detected pairs (diagnostic
                                used during the revision; no results of it are reported)
  analysis/
    analyze_small_aes.py        histogram, variance-to-mean ratio, chi-square tests against
                                the mixed Poisson prediction and a single Poisson distribution
    analyze_full_aes.py         the same for full AES
    summarize_keyrecovery.py    the key-recovery statistics of Sections 4.3 and 4.4
scripts/
  run_small_aes.sh              reproduces Results/small_aes (exact seeds)
  run_full_aes.sh               reproduces Results/aes (exact seeds)
Results/
  small_aes/distribution/       distinguisher trials, one CSV line per trial
  small_aes/keyrecovery/        key-recovery attacks, one CSV line per attack
  small_aes/p5/                 P_5(1,k) measurements
  aes/distribution/             full-AES distinguisher trials
  aes/lambda_structure/         exact lambda_S of 2,000 random full-AES structures
  aes/keyrecovery/              full-AES key-recovery attacks
  aes/keyrecovery_6r_filter/    6-round key-filtering verification
  aes/previous_100_trials/      the 100 trials of the previously submitted version
```

## Where each number of the paper comes from

| Paper | Files | Program / script |
|---|---|---|
| Table 2 (Small-AES distribution, 10^6 trials) | `Results/small_aes/distribution/A_all.csv` | `small_aes_distinguisher`, `analyze_small_aes.py` |
| Table 3 (full AES, 1,020 trials) | `Results/aes/distribution/s1_m0_*.csv`, `s1_m1_*.csv` | `distinguisher`, `analyze_full_aes.py` |
| Standard deviation 0.031 of lambda_S (Section 3.3.2) | `Results/aes/lambda_structure/FL_good.csv` (2,000 structures; the 1,020 trials of Table 3 give 0.030) | `lambda_structure.py good 2000 7` |
| P*_5(1,1) and P*_5(1,2) on Small-AES (Section 3.4) | `Results/small_aes/p5/small_aes_P5_1_1_2p32_seed20260930.txt`, `small_aes_P5_1_2_2p30_seed20260930.txt` (`P[at least one valid mask]`) | `small_aes_p5 1 4294967296 20260930`, `small_aes_p5 2 1073741824 20260930` |
| Small-AES key recovery, 10,200 attacks, 181 values per diagonal (Section 4.3) | `Results/small_aes/keyrecovery/KX181_all.csv` | `small_aes_keyrecovery` |
| Full-AES key recovery, 400 attacks, M = 44720 (D = 2^30.90 per structure) | `Results/aes/keyrecovery/e7_*.csv` | `key_recovery` |
| Full-AES key recovery, 520 attacks, M = 49312 (D = 2^31.18 per structure) | `Results/aes/keyrecovery/e4_*.csv`, `e5_*.csv`, `e6_*.csv` | `key_recovery` |
| 6-round key filtering, 200 keys (Section 4.4) | `Results/aes/keyrecovery_6r_filter/kr6f.csv` | `key_recovery_6r_filter` |

`Results/small_aes/keyrecovery/KX200_all.csv` (10,200 attacks with 200 values per diagonal)
and the Small-AES data sets other than `A_all.csv` (see below) are supplementary runs that are
not reported in the paper.

## Build

```bash
cd Codes/aes && make          # requires a CPU with AES-NI and gcc with OpenMP
cd Codes/small_aes && make
```
The analysis scripts need Python 3 with numpy (and scipy for the distribution tests).
Resources: each 2^30 distinguisher trial needs about 21 GB of memory and took about 11 minutes;
each key-recovery attack (two structures of 2^30.90 or 2^31.18 texts) needs about 49 GB and took
25-40 minutes with 4 threads; the 6-round filtering takes a few seconds per key; the Small-AES
programs run in minutes on one core.

## Usage

### Small-AES distinguisher
```bash
./small_aes_distinguisher R M1 M2 trials seed keymode [out.csv|-] [dump_threshold]
```
- `R` is the number of rounds. The 0th and 1st diagonals take `M1` and `M2` distinct random
  values; the other cells are random constants.
- `keymode 0` uses independent random round keys, `keymode 1` the same key in every round.
- Only pairs that differ in every active diagonal are considered; the exchanged pair is looked
  up by index.
- CSV output, one line per trial (no header): `classes, right_classes, N_rc`.
- The program also prints a summary with the number of trials that contained an odd number of
  detected pairs (`parity_viol`); it was 0 in all our runs (Section 3.3.1). These stdout summaries are
  not included in the repository; rerunning `scripts/run_small_aes.sh` regenerates them under `runs/`.

### Small-AES key recovery
```bash
./small_aes_keyrecovery R M trials seed
```
The CSV columns are described in the header of the source file. Among other fields, each line
records whether the correct key survives the elimination approach (`strict_ok`), whether it is
recovered with the count rule (`exact2_ok`), and the count of the correct key in each
structure (`ktrue1`, `ktrue2`).

### Full-AES distinguisher
```bash
./distinguisher R L trials mode seed [first_trial] [pairlog]
```
- `R` is the number of rounds, and each active diagonal takes `2^L` values (`L = 15` gives
  2^30 texts).
- `mode 0` uses a 64-bit generator with distinct values; `mode 1` uses glibc `rand()` in the
  order of the program of the previous version and draws the values with replacement, so a
  structure may contain a few duplicate diagonal values (columns `dupA`, `dupB`). Pairs that are
  equal on an active diagonal are excluded in both modes, as required by Theorem 2, and
  `deg_collide` counts the excluded colliding pairs. Table 3 pools 510 trials of each mode.
- `pairlog` (default on): if nonzero, every detected pair is written to stderr as an `RP` line
  (indices, right/not-right label, zero masks); pass 0 to disable.
- CSV output: `trial,mode,seed,pairs,classes,right_classes,N_rc,lambda_S,dupA,dupB,deg_collide,parity_ok,secs`
  (no header line; the source comments use the earlier names `trail_classes` and `M_S`).

### Full-AES key recovery
```bash
./key_recovery M attacks seed first threads          # M values per active diagonal (multiple of 8)
./key_recovery 0 attacks seed first threads nt nf    # synthetic test: nt right + nf other classes
```
CSV columns (`Results/aes/keyrecovery/columns.txt`):
`attack,seed,M,n0,f0,n1,f1,cons0,cons1,cand0,cand1,top0,ntop0,nge0,top1,ntop1,nge1,log2_total,log2_tiered,found,weak_strict_ok,secs`,
where `n` is the number of detected classes and `f` the number of them that are not right
classes per structure, `cons` the count of the correct key, `cand` the size of the candidate
list, `nge` the number of candidates ranked at least as high as the correct key,
`log2_total` the log2 of |L0|·|L1|, `log2_tiered` the log2 of the number of candidates ranked at
least as high as the correct key in both structures (the cost of the ranked search of Algorithm 3;
the 2^25 and 2^32 figures of Section 4.3 are this column), `found` whether the key was recovered
(by trial encryption when |L0|·|L1| <= 2^28, otherwise by checking that the correct key is in both
lists), and `weak_strict_ok` whether the correct key passes the weak zero-byte test of the
previously submitted version for every detected class (not used in the paper). The elimination
approach of the paper keeps the correct key exactly when `f0 = f1 = 0`.
The summary statistics of Section 4.3 are printed by `python3 Codes/analysis/summarize_keyrecovery.py`.

### 6-round key filtering
```bash
./key_recovery_6r_filter trials seed threads
```
For each trial, two right classes of the 6-round attack are generated under a random key and
the filtering of Observation 2 is run over all 2^32 guesses of each active diagonal. Columns:
`Results/aes/keyrecovery_6r_filter/columns.txt`.

### Analysis
```bash
python3 Codes/analysis/analyze_small_aes.py A=Results/small_aes/distribution/A_all.csv
python3 Codes/analysis/analyze_full_aes.py "Results/aes/distribution/s1_m*.csv"   # pooled 1,020 trials (Table 3)
```

## Small-AES data sets (`Results/small_aes/distribution`)

| File | Rounds | Values per diagonal | Trials | Key schedule | Seeds | In the paper |
|---|---|---|---|---|---|---|
| `A_all.csv` | 5 | 2^7 | 10^6 | independent | 1001–1016 | Table 2 |
| `B_all.csv` | 5 | 2^7 | 2·10^5 | same key | 2001–2008 | supplementary |
| `D64_all.csv` | 5 | 2^6 | 2·10^5 | independent | 3001–3004 | supplementary |
| `E256_all.csv` | 5 | 2^8 | 5·10^4 | independent | 4001–4004 | supplementary |
| `C5_all.csv` | 5 | 2^9 | 2·10^4 | independent | 6001–6016 | supplementary |
| `C8_all.csv` | 8 | 2^9 | 2·10^4 | independent | 5001–5016 | supplementary |

The supplementary sets test the model with the same key in every round (B), with structures of
2^12 and 2^16 plaintexts (D64, E256), and at 2^18 plaintexts with 5 rounds (C5) against an 8-round
control without exchange trail (C8); all are analysed with `analyze_small_aes.py <label>=<file>`.
The files have no header line.

Key-recovery files: `KX181_all.csv` (181 values per diagonal, seeds 9101–9112; Section 4.3)
and `KX200_all.csv` (200 values per diagonal, seeds 9001–9012; supplementary).

The P_5 measurements in `Results/small_aes/p5/` were produced by `small_aes_p5`; the file
`small_aes_P5_1_1_2p32_seed20260930.txt` (2^32 pairs that differ in every active diagonal, seed
20260930) is the run quoted in Section 3.4, whose `P[at least one valid mask]` line is the
empirical P*_5(1,1) = 2^-17.95; `small_aes_P5_1_2_2p30_seed20260930.txt` gives P*_5(1,2) = 2^-12.41 in the
same way. The older files without a seed in their name were produced by the previous
version of the program, which was seeded from the clock and did not require the pairs to differ
in every active diagonal.

## License

This project is licensed under the MIT License; see [LICENSE](LICENSE).

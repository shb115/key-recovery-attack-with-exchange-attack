# Revisiting Exchange Distinguisher and Key-Recovery Attacks on Reduced-Round AES

Code, raw results, and random seeds for the experiments of the paper

**"Revisiting Exchange Distinguisher and Key-Recovery Attacks on Reduced-Round AES"**
Hanbeom Shin, Byoungjin Seok, Dongjae Lee, Deukjo Hong, Jaechul Sung, Seokhie Hong.

## Overview

The experiments cover:

1. **Distribution of the number of detected classes** of the 5-round exchange distinguisher.
   Right pairs occur in classes of size two (Theorem 2). The number of detected classes is
   modeled by a Poisson distribution conditional on the plaintext structure,
   `N | S ~ Pois(lambda_S)` with `lambda_S = M_S * q + N_cls * 2^-62` (Section 3.2).
   Here `M_S` is the number of classes of the structure that satisfy the one-round exchange
   condition. The model is tested on Small-Scale AES with 10^6 trials (Section 3.3.1) and on
   full AES (Section 3.3.2).
2. **Key recovery without key-guessing rounds** (Section 4). The attack uses the exact
   first-round zero-byte patterns (Observation 1) and the rule "keep the key guesses
   consistent with at least two detected classes, ranked by the number of consistent
   classes". The attack is run end to end on Small-Scale AES and on full AES.

## Repository structure

```
Codes/
  aes/                          full AES (AES-NI)
    exchange_distinguisher.c    5-round distinguisher, 2^(2L) texts per trial, per-trial
                                class counts, trail/non-trail labels, exact M_S and lambda_S
    exchange_keyrecovery.c      end-to-end 5-round key recovery (two structures), exact
                                pattern filter, ranked candidates, known-pair verification;
                                M = 0 runs a synthetic test of the filter
    lambda_structure.py         exact lambda_S of random full-AES structures without
                                encryption (also with the glibc / MSVCRT rand() streams)
    legacy/                     code of the previous version of the paper
  small_aes/                    Small-Scale AES with 4-bit cells
    small_aes_distinguisher.c   5-round distinguisher (class counts, trail labels, M_S)
    small_aes_keyrecovery.c     end-to-end key recovery (previous filter vs. new rule)
    small_aes_r2_diagnostic.c   zero cells / diagonals of the 2-round difference of detected pairs
    small_aes_p5.c              direct measurement of the one-round probability P_5(1,k)
  analysis/
    analyze_small_aes.py        histogram, index of dispersion, chi-square tests
                                (single Poisson and mixed Poisson), conditional analysis
    analyze_full_aes.py         the same for full AES, with tests using the known lambda_S
scripts/
  run_small_aes.sh              reproduces Results/small_aes (exact seeds)
  run_full_aes.sh               full-AES distinguisher and key-recovery runs
Results/
  small_aes/distribution/       per-trial CSV files (see below)
  small_aes/keyrecovery/        per-attack CSV file
  small_aes/p5/                 P_5(1,k) measurements
  aes/lambda_structure/         exact lambda_S of random full-AES structures
  aes/distribution/             full-AES distinguisher runs
  aes/keyrecovery/              full-AES key-recovery runs
  aes/previous_100_trials/      results of the previous version (100 trials)
```

## Build

```bash
cd Codes/aes && make          # requires AES-NI and gcc with OpenMP
cd Codes/small_aes && make
```

## Usage

### Small-Scale AES distinguisher
```bash
./small_aes_distinguisher R M1 M2 trials seed keymode [out.csv|-] [dump_threshold]
```
- `R` is the number of rounds. The 0th and 1st diagonals take `M1` and `M2` distinct random
  values; the other cells are random constants.
- `keymode 0` uses independent random round keys, and `keymode 1` uses the same key in every
  round.
- Pairs that are equal on an active diagonal (degenerate pairs) are skipped. The exchanged
  pair is looked up by index.
- CSV output, one line per trial: `classes, trail_classes, M_S`.

### Small-Scale AES key recovery
```bash
./small_aes_keyrecovery R M trials seed
```
CSV columns are described in the header of the source file. Among other fields, they record
whether the correct key survives the previous filter (`strict_ok`) and whether it is
recovered with the new rule (`exact2_ok`).

### Full-AES distinguisher
```bash
./distinguisher R L trials mode seed [first_trial] [pairlog]
```
- `R` is the number of rounds, and each active diagonal takes `2^L` values (`L = 15` gives
  2^30 texts).
- `mode 0` uses a 64-bit generator with distinct values. `mode 1` uses glibc `rand()` in the
  exact order of the previous program, so that a run with seed `S` reproduces the previous
  program patched with `srand(S)`.
- CSV output: `trial,mode,seed,pairs,classes,trail_classes,M_S,lambda_S,dupA,dupB,deg_collide,parity_ok,secs`.
- With 4 rounds (every non-degenerate colliding pair is a right pair), the per-trial counts
  were checked to coincide exactly with those of the previous program for the same seeds.

### Full-AES key recovery
```bash
./key_recovery M attacks seed first threads          # M values per active diagonal
./key_recovery 0 attacks seed first threads nt nf    # synthetic test: nt trail + nf random classes
```

### Analysis
```bash
python3 Codes/analysis/analyze_small_aes.py A=Results/small_aes/distribution/A_all.csv
python3 Codes/analysis/analyze_full_aes.py 'Results/aes/distribution/s1_m0_*.csv'
```

## Small-Scale AES data sets (`Results/small_aes/distribution`)

| File | Rounds | Values per diagonal | Trials | Key schedule | Seeds |
|---|---|---|---|---|---|
| `A_all.csv` | 5 | 2^7 | 10^6 | independent | 1001–1016 |
| `B_all.csv` | 5 | 2^7 | 2·10^5 | same key | 2001–2008 |
| `D64_all.csv` | 5 | 2^6 | 2·10^5 | independent | 3001–3004 |
| `E256_all.csv` | 5 | 2^8 | 5·10^4 | independent | 4001–4004 |
| `C5_all.csv` | 5 | 2^9 | 2·10^4 | independent | 6001–6016 |
| `C8_all.csv` | 8 | 2^9 | 2·10^4 | independent | 5001–5016 |

The key-recovery file `Results/small_aes/keyrecovery/KX200_all.csv` contains 10,200 attacks
with 200 values per diagonal (seeds 9001–9012).

## License

This project is licensed under the MIT License; see [LICENSE](LICENSE).

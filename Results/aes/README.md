# Full-AES results

All CSV files have no header line; the columns are listed below or in `columns.txt`.

- `distribution/`: 5-round distinguisher, D = 2^30, 1,020 trials (Table 3; `scripts/run_full_aes.sh`).
  `s1_m0_p*.csv`: 64-bit generator with distinct diagonal values (seed 20260928, trials 0-509);
  `s1_m1_p*.csv`: glibc rand() in the order of the program of the previous version (srand(1000001+p), 17 trials each).
  Columns: `trial,mode,seed,pairs,classes,right_classes,N_rc,lambda_S,dupA,dupB,deg_collide,parity_ok,secs`
  (the source comments use the earlier names `trail_classes` and `M_S`).
  Analysis: `python3 Codes/analysis/analyze_full_aes.py "Results/aes/distribution/s1_m*.csv"`.
- `keyrecovery/`: complete 5-round key-recovery attacks (Section 4.3), 4 threads each; columns in `columns.txt`.
  `e7_p*.csv`: 400 attacks with M = 44720 values per diagonal (D = 2^30.90 per structure, the parameters of the
  attack), seed 20260930, attack ids 0-399; 240 recovered the key.
  `e4_p*.csv`, `e5_p*.csv`, `e6_p*.csv`: 520 attacks with M = 49312 (D = 2^31.18), seed 20260929, ids 0-19, 20-219
  and 220-519; 465 recovered the key.
  Summary: `python3 Codes/analysis/summarize_keyrecovery.py`.
- `keyrecovery_6r_filter/`: verification of the 6-round key filtering (Section 4.4) with synthetic right classes
  (`Codes/aes/exchange_keyrecovery_6r_filter.c`, 200 keys, seed 20260930); columns in `columns.txt`.
- `lambda_structure/`: exact lambda_S of random structures (`Codes/aes/lambda_structure.py`);
  `FL_good.csv` = 2,000 structures with the 64-bit generator (mode `good`, seed 7), the source of the standard
  deviation 0.031 quoted in Section 3.3.2; the `FL_glibc_*` and `FL_msvc_*` files are 100-structure pilot runs
  with the C-library generators of the previous version.
- `previous_100_trials/`: the 100 trials of the previously submitted version, kept for reference.

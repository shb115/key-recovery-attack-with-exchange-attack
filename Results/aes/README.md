# Full-AES results

- `distribution/`: 5-round distinguisher, D = 2^30, 1,020 trials (`scripts/run_full_aes.sh`).
  `s1_m0_p*.csv`: 64-bit generator with distinct diagonal values (seed 20260928, trials 0-509);
  `s1_m1_p*.csv`: glibc rand() in the order of the previous program (srand(1000001+p), 17 trials each).
  Columns: trial,mode,seed,pairs,classes,trail_classes,M_S,lambda_S,dupA,dupB,deg_collide,parity_ok,secs.
  Analysis: `python3 Codes/analysis/analyze_full_aes.py "Results/aes/distribution/s1_m*.csv"`.
- `keyrecovery/`: 220 complete 5-round key-recovery attacks with D = 2^31.18 per structure (M = 49312 values per diagonal, seed 20260929, attack ids 0-219, 4 threads each: `e4_*` = ids 0-19, `e5_*` = ids 20-219); columns in `columns.txt`. 192 of 220 (87.3%) recovered the key.
- `lambda_structure/`: exact lambda_S of random structures (`Codes/aes/lambda_structure.py`).
- `previous_100_trials/`: results of the previous version of the paper.
- `keyrecovery_6r_filter/`: verification of the 6-round key filtering with synthetic right class pairs (`Codes/aes/exchange_keyrecovery_6r_filter.c`, 200 trials, seed 20260930); columns in `columns.txt`.

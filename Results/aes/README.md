# Full-AES results

- `distribution/`: 5-round distinguisher, D = 2^30, 1,020 trials (`scripts/run_full_aes.sh`).
  `s1_m0_p*.csv`: 64-bit generator with distinct diagonal values (seed 20260928, trials 0-509);
  `s1_m1_p*.csv`: glibc rand() in the order of the previous program (srand(1000001+p), 17 trials each).
  Columns: trial,mode,seed,pairs,classes,trail_classes,M_S,lambda_S,dupA,dupB,deg_collide,parity_ok,secs.
  Analysis: `python3 Codes/analysis/analyze_full_aes.py "Results/aes/distribution/s1_m*.csv"`.
- `keyrecovery/`: complete 5-round key-recovery attacks with D = 2^31.18 per structure (added when complete).
- `lambda_structure/`: exact lambda_S of random structures (`Codes/aes/lambda_structure.py`).
- `previous_100_trials/`: results of the previous version of the paper.

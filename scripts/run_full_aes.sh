#!/bin/bash
# Full-AES experiments of Section 3.3.2 and Section 4.3 (Linux, AES-NI, gcc + OpenMP).
# Memory: about 21 GB per distinguisher process (2^30 texts) and about 49 GB per
# key-recovery process (2^31.18 texts per structure). Adjust the numbers of
# parallel processes to the machine.
set -e
cd "$(dirname "$0")/../Codes/aes" && make
OUT=../../Results/aes
mkdir -p $OUT/distribution $OUT/keyrecovery $OUT/logs
# 5-round distinguisher, D = 2^30:
#  mode 0: 64-bit generator, distinct diagonal values, trial ids p*17 .. p*17+16 (seed 20260928)
#  mode 1: glibc rand() in the order of the previous experiment, srand(1000001+p)
for p in $(seq 0 29); do nice -n 10 ./distinguisher 5 15 17 0 20260928 $((p*17)) 1 > $OUT/distribution/s1_m0_p$p.csv 2> $OUT/logs/s1_m0_p$p.err & done
for p in $(seq 0 29); do nice -n 10 ./distinguisher 5 15 17 1 $((1000001+p)) 0 1 > $OUT/distribution/s1_m1_p$p.csv 2> $OUT/logs/s1_m1_p$p.err & done
wait
python3 ../analysis/analyze_full_aes.py "$OUT/distribution/s1_m0_*.csv" "$OUT/distribution/s1_m1_*.csv"
# 5-round key recovery, D = 2^31.18 per structure (M = 49312 values per diagonal), 20 attacks
for p in 0 1 2 3 4; do nice -n 10 ./key_recovery 49312 4 20260929 $((p*4)) 4 > $OUT/keyrecovery/e4_p$p.csv 2> $OUT/logs/e4_p$p.err & done
wait
# 200 further attacks (ids 20-219)
for p in $(seq 0 19); do nice -n 10 ./key_recovery 49312 10 20260929 $((20+p*10)) 4 > $OUT/keyrecovery/e5_p$p.csv 2> $OUT/logs/e5_p$p.err & done
wait
# 300 further attacks (ids 220-519)
for p in $(seq 0 19); do nice -n 10 ./key_recovery 49312 15 20260929 $((220+p*15)) 4 > $OUT/keyrecovery/e6_p$p.csv 2> $OUT/logs/e6_p$p.err & done
wait

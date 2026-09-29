#!/bin/bash
# Reproduces the Small-Scale AES results of Section 3.3.1 and Section 4.3
# (exact seeds used for the files in Results/small_aes/).
# Each configuration is split into independent processes that run in parallel.
set -e
cd "$(dirname "$0")/../Codes/small_aes" && make
OUT=../../Results/small_aes
mkdir -p $OUT/distribution/runs $OUT/keyrecovery/runs
D=$OUT/distribution/runs
# A: 5 rounds, 2^7 values per diagonal (D = 2^14), independent round keys, 10^6 trials
for s in $(seq 1 16); do ./small_aes_distinguisher 5 128 128 62500 $((1000+s)) 0 $D/A_$s.csv > $D/A_$s.txt & done; wait
# B: same key in every round, 2x10^5 trials
for s in $(seq 1 8); do ./small_aes_distinguisher 5 128 128 25000 $((2000+s)) 1 $D/B_$s.csv > $D/B_$s.txt & done
# D64 / E256: structures with 2^6 and 2^8 values per diagonal
for s in $(seq 1 4); do ./small_aes_distinguisher 5 64 64 50000 $((3000+s)) 0 $D/D64_$s.csv > $D/D64_$s.txt & done
for s in $(seq 1 4); do ./small_aes_distinguisher 5 256 256 12500 $((4000+s)) 0 $D/E256_$s.csv > $D/E256_$s.txt & done; wait
# C8: 8-round control (no trail), 2^9 values per diagonal; C5: 5 rounds, 2^9 values per diagonal
for s in $(seq 1 16); do ./small_aes_distinguisher 8 512 512 1250 $((5000+s)) 0 $D/C8_$s.csv > $D/C8_$s.txt & done; wait
for s in $(seq 1 16); do ./small_aes_distinguisher 5 512 512 1250 $((6000+s)) 0 $D/C5_$s.csv > $D/C5_$s.txt & done; wait
# Key recovery: 10,200 attacks, 200 values per diagonal (lambda_T ~ 4.45 per structure)
K=$OUT/keyrecovery/runs
for s in $(seq 1 12); do ./small_aes_keyrecovery 5 200 850 $((9000+s)) > $K/KX200_$s.csv & done; wait
# Key recovery at the parameters of the attack: 10,200 attacks, 181 values per diagonal (lambda_T ~ 3.03 per structure)
for s in $(seq 1 12); do ./small_aes_keyrecovery 5 181 850 $((9100+s)) > $K/KX181_$s.csv & done; wait
for x in A B D64 E256 C8 C5; do cat $D/${x}_*.csv > $OUT/distribution/${x}_all.csv; done
cat $K/KX200_*.csv > $OUT/keyrecovery/KX200_all.csv
cat $K/KX181_*.csv > $OUT/keyrecovery/KX181_all.csv
python3 ../analysis/analyze_small_aes.py A=$OUT/distribution/A_all.csv

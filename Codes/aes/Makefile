# Full-AES experiments (requires a CPU with AES-NI, gcc with OpenMP).
#   distinguisher : 5-round exchange distinguisher, per-trial class counts and lambda_S
#   key_recovery  : end-to-end 5-round key recovery (two structures)
#   key_recovery_6r_filter : 6-round key filtering (Observation 2) on synthetic right classes
CC = gcc
CFLAGS = -O3 -maes -mssse3 -msse4.1 -Wall

all: distinguisher key_recovery key_recovery_6r_filter

distinguisher: exchange_distinguisher.c
	$(CC) $(CFLAGS) -o $@ $<

key_recovery: exchange_keyrecovery.c
	$(CC) $(CFLAGS) -fopenmp -o $@ $< -lm

key_recovery_6r_filter: exchange_keyrecovery_6r_filter.c
	$(CC) $(CFLAGS) -fopenmp -o $@ $< -lm

clean:
	rm -f distinguisher key_recovery key_recovery_6r_filter

.PHONY: all clean

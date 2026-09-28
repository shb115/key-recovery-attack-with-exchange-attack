# Full-AES experiments (requires a CPU with AES-NI, gcc with OpenMP).
#   distinguisher : 5-round exchange distinguisher, per-trial class counts and lambda_S
#   key_recovery  : end-to-end 5-round key recovery (two structures)
CC = gcc
CFLAGS = -O3 -maes -mssse3 -msse4.1 -Wall

all: distinguisher key_recovery

distinguisher: exchange_distinguisher.c
	$(CC) $(CFLAGS) -o $@ $<

key_recovery: exchange_keyrecovery.c
	$(CC) $(CFLAGS) -fopenmp -o $@ $< -lm

clean:
	rm -f distinguisher key_recovery

.PHONY: all clean

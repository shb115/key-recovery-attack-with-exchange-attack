# Small-Scale AES experiments (4-bit cells); no special instruction set needed.
CC = gcc
CFLAGS = -O3 -Wall
LDFLAGS = -lm
TARGETS = small_aes_distinguisher small_aes_keyrecovery small_aes_r2_diagnostic small_aes_p5

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean

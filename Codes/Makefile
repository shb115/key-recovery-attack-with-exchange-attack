# Compiler settings
CC = gcc

# Compiler flags
# -O3       : Optimize for maximum speed
# -maes     : Enable AES-NI instruction set (Required for _mm_aesenc_si128)
# -msse4.1  : Enable SSE4.1 instructions (Required for some SIMD operations)
# -Wall     : Enable all standard warnings
CFLAGS = -O3 -maes -msse4.1 -Wall

# Target executable names
TARGET1 = distinguisher
TARGET2 = key_recovery

# Source file names
SRC1 = exchange_distinguisher.c
SRC2 = exchange_keyrecovery.c

# ---------------------------------------------------------------------------
# Build Rules
# ---------------------------------------------------------------------------

# Default target: Build both executables
all: $(TARGET1) $(TARGET2)

# Rule to build the distinguisher
$(TARGET1): $(SRC1)
	$(CC) -o $(TARGET1) $(SRC1) $(CFLAGS)
	@echo "Built $(TARGET1) successfully."

# Rule to build the key recovery attack
$(TARGET2): $(SRC2)
	$(CC) -o $(TARGET2) $(SRC2) $(CFLAGS)
	@echo "Built $(TARGET2) successfully."

# Clean rule: Remove both executables
clean:
	rm -f $(TARGET1) $(TARGET2)

.PHONY: all clean
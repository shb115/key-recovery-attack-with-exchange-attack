# Compiler settings
CC = gcc

# Compiler flags
# -O3   : Optimize for maximum speed
# -Wall : Enable all standard warnings
# (AES-NI is not required here; Small-AES uses 4-bit-cell T-tables.)
CFLAGS = -O3 -Wall

# Linker flags
# -lm   : Link the math library (used for the log/exp/factorial computations)
LDFLAGS = -lm

# Target executable name
TARGET = small_aes_p5

# Source file name
SRC = small_aes_p5.c

# ---------------------------------------------------------------------------
# Build Rules
# ---------------------------------------------------------------------------

# Default target: Build the executable
all: $(TARGET)

# Rule to build the Small-AES P_5 measurement
$(TARGET): $(SRC)
	$(CC) -o $(TARGET) $(SRC) $(CFLAGS) $(LDFLAGS)
	@echo "Built $(TARGET) successfully."

# Clean rule: Remove the executable
clean:
	rm -f $(TARGET)

.PHONY: all clean

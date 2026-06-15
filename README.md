# Key-Recovery Attacks on Reduced-Round AES with Exchange Attacks

This repository contains the proof-of-concept implementation of the key-recovery attacks presented in our paper:

**"Revisiting Exchange Distinguisher and Key-Recovery Attacks on Reduced-Round AES"**

* **Authors:** Hanbeom Shin, Byoungjin Seok, Dongjae Lee, Deukjo Hong, Jaechul Sung, Seokhie Hong.

## Overview

This project implements the **Exchange Distinguisher** and **Key-Recovery Attack** on **5-round AES**. The implementation focuses on verifying the theoretical claims regarding:

1.  **Equivalence Classes:** Validating that right pairs appear in groups of two (Theorem 2).
2.  **Probabilistic Model:** Verifying the refined success probabilities based on the equivalence class structure.
3.  **Key Recovery:** Demonstrating the attack utilizing the zero-difference property in non-zero columns (Observation 1) without key-guessing rounds.

In addition, a **Small-Scale AES** experiment directly measures the one-round exchange probability `P_5(1,k)`, which underlies the **6-round** distinguisher whose full simulation is computationally infeasible.

> **Note:** The full-AES code is written in **C** and optimized using **AES-NI (Intel Advanced Encryption Standard New Instructions)** for high-performance verification. The Small-Scale AES code uses 4-bit-cell T-tables and requires no special instruction set.

## Repository Structure

The full-AES and Small-Scale AES implementations are placed in the `aes/` and `small_aes/` subdirectories of `Codes/` (and likewise under `Results/`).

* **`Codes/aes/exchange_distinguisher.c`**
    * Implements the **5-round** exchange distinguisher.
    * Verifies the distribution of right pairs and the formation of equivalence classes.
    * Counts the number of detected pairs and validates the theoretical probability model.

* **`Codes/aes/exchange_keyrecovery.c`**
    * Implements the **5-round** key-recovery attack logic.
    * Performs the 5-round key-recovery attack using the structural properties of right pairs.
    * Verifies the filtering condition (Observation 1) and calculates the success rate of the attack.

* **`Codes/small_aes/small_aes_p5.c`**
    * Directly measures the one-round exchange probability `P_5(1,k)` on **Small-Scale AES** (4-bit cells), by checking the exact algebraic one-round exchange condition.
    * `k = 2` corresponds to the 5-round trail and `k = 1` to the 6-round trail.
    * Evaluates the same `P_5(1,1)` formula on Small-Scale AES, where it gives `~= 2^-17.87` (the full-AES value, `2^-38`, is infeasible to measure directly), empirically supporting the probabilistic model used for the 6-round distinguisher.

* **`Makefile`** (one in each `Codes` subdirectory)
    * Build scripts to compile the executables with the appropriate optimization flags (`-O3`, plus `-maes`, `-msse4.1` for the AES-NI code).

## Prerequisites

* **Compiler:** GCC (GNU Compiler Collection)
* **Hardware:** For the full-AES code, a CPU with **AES-NI** support (most modern Intel/AMD processors). The Small-Scale AES code has no such requirement.
* **OS:** Linux (Recommended) or macOS.

## Build Instructions

Each component is built from its own directory using the provided `Makefile`.

1.  **Full AES (distinguisher and key recovery):**
    ```bash
    cd Codes/aes
    make
    ```
    This command will generate two executables: `distinguisher` and `key_recovery`.

2.  **Small-Scale AES (P_5 measurement):**
    ```bash
    cd Codes/small_aes
    make
    ```
    This command will generate the executable `small_aes_p5`.

3.  **(Optional) Clean up build files:**
    ```bash
    make clean
    ```

## Usage

### 1. Running the Distinguisher
To verify the equivalence class structure and the probability of the 5-round exchange distinguisher:

```bash
./distinguisher
```

* **Goal:** This verifies whether the right pairs appear in even numbers (equivalence classes).
* **Output:** The number of right pairs found in each trial (default: 100 trials).

### 2. Running the Key Recovery Attack
To verify the validity of the 5-round key-recovery attack logic:

```bash
./key_recovery
```

* **Goal:** This verifies the logic of the 5-round key recovery attack.
* **Process:** It generates structures, identifies right pairs, and applies the filtering logic to check if the correct key passes and wrong keys are filtered as expected.
* **Output:** Verification logs showing "Right Pair Found", "Correct Key PASS", and "Wrong Key" filtering statistics.

### 3. Running the Small-Scale AES P_5 Measurement
To directly measure the one-round exchange probability `P_5(1,k)`:

```bash
./small_aes_p5 [k] [trials]
```

* **Arguments:** `k` (1 or 2; default 1) and the number of `trials` (default 2^28). The random number generator is seeded from the system clock (no seed argument), so runs started at different times draw independent samples.
* **Goal:** This verifies the trail-probability formula `P_5(1,k)` used in the 5- and 6-round distinguishers.
* **Output:** The expected and measured values of `P_5(1,k)` (e.g., `P_5(1,1) ~= 2^-17.87`), together with the per-weight breakdown.

## Experimental Results

The experimental results provided by these codes support the claims made in the paper:

* **Equivalence Classes:** Right pairs are consistently found in multiples of 2.
* **Success Probability:** The experimental success rate aligns with our refined probabilistic model (approx. 54% for the standard structure size), deviating from the previous independent trial assumption.
* **Trail Probability (Small-Scale AES):** The measured `P_5(1,1)` matches the formula `2^-17.87` (and `P_5(1,2)` matches `2^-12.19`), supporting the probabilistic model used for the 6-round distinguisher.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

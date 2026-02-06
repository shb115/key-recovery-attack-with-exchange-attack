# Key-Recovery Attacks on Reduced-Round AES with Exchange Attacks

This repository contains the proof-of-concept implementation of the key-recovery attacks presented in our paper:

**"Revisiting Exchange Distinguisher and Key-Recovery Attacks on Reduced-Round AES"**

* **Authors:** Hanbeom Shin, Byoungjin Seok, Dongjae Lee, Deukjo Hong, Jaechul Sung, Seokhie Hong.

## Overview

This project implements the **Exchange Distinguisher** and **Key-Recovery Attacks** on reduced-round AES. The implementation focuses on verifying the theoretical claims regarding:

1.  **Equivalence Classes:** Validating that right pairs appear in groups of two (Theorem 2).
2.  **Probabilistic Model:** Verifying the refined success probabilities based on the equivalence class structure.
3.  **Key Recovery:** Demonstrating the attack utilizing the zero-difference property in non-zero columns (Observation 1) without key-guessing rounds.

> **Note:** The code is written in **C** and optimized using **AES-NI (Intel Advanced Encryption Standard New Instructions)** for high-performance verification.

## Repository Structure

The implementation consists of the following main components:

* **`exchange_distinguisher.c`**
    * Implements the 5-round exchange distinguishers.
    * Verifies the distribution of right pairs and the formation of equivalence classes.
    * Counts the number of detected pairs and validates the theoretical probability model.

* **`exchange_keyrecovery.c`**
    * Implements the key-recovery attack logic.
    * Performs the 5-round key-recovery attack using the structural properties of right pairs.
    * Verifies the filtering condition (Observation 1) and calculates the success rate of the attack.

* **`Makefile`**
    * A build script to compile both the distinguisher and key recovery executables with necessary optimization flags (`-O3`, `-maes`, `-msse4.1`).

## Prerequisites

To run the code, you need a system that supports the **AES-NI** instruction set.

* **Compiler:** GCC (GNU Compiler Collection)
* **Hardware:** CPU with AES-NI support (most modern Intel/AMD processors).
* **OS:** Linux (Recommended) or macOS.

## Build Instructions

You can easily compile the source codes using the provided `Makefile`.

1.  **Compile the executables:**
    ```bash
    make
    ```
    This command will generate two executables: `distinguisher` and `key_recovery`.

2.  **(Optional) Clean up build files:**
    ```bash
    make clean
    ```

## Usage

### 1. Running the Distinguisher
To verify the equivalence class structure and the probability of the exchange distinguisher:

```bash
./distinguisher

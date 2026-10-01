# DFA against SFLL-Protected SIMECK32/64

Experimental implementation of **Differential Fault Analysis (DFA)** against the lightweight block cipher **SIMECK32/64** protected by Logic Locking and **SFLL-HD**.

This project simulates fault attacks on SIMECK32/64 and attempts to recover the round keys \(K_{31}\)–\(K_{28}\), followed by reconstruction and verification of the master key.

## Overview

The project evaluates DFA under the following three configurations:

1. SIMECK32/64 without Logic Locking
2. SIMECK32/64 with XOR-based Logic Locking
3. SIMECK32/64 with SFLL-HD

For the XOR-based Logic Locking configuration, Logic Locking is applied to all 32 rounds.

For the SFLL configuration, SFLL is applied to all 32 rounds. A perturbation is introduced when the Hamming distance between the internal state and the secret pattern satisfies the specified SFLL-HD condition.

The current implementation mainly focuses on recovering the last four round keys:

```text
K31
K30
K29
K28
```

These round keys are then used to reverse the SIMECK key schedule and reconstruct the master key.

---

## Attack Flow

The attack simulation consists of the following steps:

```text
STEP 1  Initialize cipher parameters and keys

STEP 2  Obtain a fault-free ciphertext
        under the selected Logic Locking configuration

STEP 3  Inject a fault into round 30
        and recover K31

STEP 4  Inject a fault into round 29
        and recover K30

STEP 5  Inject a fault into round 28
        and recover K29

STEP 6  Inject a fault into round 27
        and recover K28

STEP 7  Output the recovered round keys

STEP 8  Reverse the key schedule and verify
        the recovered master key
```

Conceptually:

```text
Plaintext
   |
   v
SIMECK32/64
   |
   +---- Logic Locking / SFLL-HD
   |
   +---- Fault Injection
   |
   v
Faulty Ciphertext
   |
   v
Differential Fault Analysis
   |
   v
K31 -> K30 -> K29 -> K28
   |
   v
Reverse Key Schedule
   |
   v
Recovered Master Key
```

---

## Project Structure

### Main Programs

#### `no_ll_main.c`

Main program for SIMECK32/64 without Logic Locking.

#### `with_ll_main.c`

Main program for SIMECK32/64 with XOR-based Logic Locking.

Logic Locking is applied to all 32 rounds.

#### `with_sfll_main.c`

Main program for SIMECK32/64 with SFLL-HD protection.

This program performs the DFA attack while SFLL perturbations are present.

---

## Encryption

Files:

```text
encryption.c
encryption.h
```

These files implement SIMECK32/64 encryption.

Both fault-free and fault-injected encryption functions are provided.

### Fault-free Encryption

```c
true_encryption()
true_ll_encryption()
true_sfll_encryption()
```

These functions are mainly used in **STEP 2**.

They generate the reference ciphertext without fault injection.

### Fault-injected Encryption

```c
fault_encryption()
fault_ll_encryption()
fault_sfll_encryption()
```

These functions are used in **STEP 3–6**.

They simulate fault injection into a selected round and generate the corresponding faulty ciphertext.

---

## Differential Fault Analysis

Files:

```text
dfa.c
dfa.h
```

The attacker injects a fault into round \(T-1\) and attempts to recover the round key \(K_T\).

The DFA implementation is based on the fault analysis methodology described in:

> D.-P. Le, R. Lu, and A. A. Ghorbani,  
> "Improved Fault Analysis on SIMECK Ciphers."

### DFA without SFLL

```c
dfa_k31()
dfa_k30()
dfa_k29()
dfa_k28()
```

These functions are used for:

- SIMECK without Logic Locking
- SIMECK with XOR-based Logic Locking

### DFA with SFLL

```c
dfa_with_sfll_k31()
dfa_with_sfll_k30()
dfa_with_sfll_k29()
dfa_with_sfll_k28()
```

These functions perform DFA while SFLL perturbations are present.

---

## Master Key Recovery

Files:

```text
decryption.c
decryption.h
```

After recovering four consecutive round keys:

```text
K28
K29
K30
K31
```

the attacker reverses the SIMECK32/64 key schedule.

### Function

```c
recover_master_key()
```

Input:

```text
K28, K29, K30, K31
```

Output:

```text
K0, K1, K2, K3
```

The recovered master key is then compared with the original key to verify whether the attack was successful.

---

## Test Program

```text
test_main.c
```

This file contains code used for testing and debugging individual components of the implementation.

---

## Build

A C compiler such as GCC is required.

### SFLL-HD version

```bash
gcc with_sfll_main.c encryption.c dfa.c decryption.c -o main
./main
```

### XOR Logic Locking version

```bash
gcc with_ll_main.c encryption.c dfa.c decryption.c -o main
./main
```

### No Logic Locking version

```bash
gcc no_ll_main.c encryption.c dfa.c decryption.c -o main
./main
```

For additional compiler warnings:

```bash
gcc -Wall -Wextra with_sfll_main.c encryption.c dfa.c decryption.c -o main
```

---

## Current Research Focus

When SFLL is enabled, some observed differences do not follow the original SIMECK fault-difference propagation.

As a result, DFA may fail to correctly identify:

- the injected fault position
- the corresponding round-key bits

In the current model, some observed differences can be represented conceptually as:

```text
observed difference = true difference XOR SFLL-induced difference
```

If the attacker knows the SFLL key or the SFLL-induced perturbation, it may be possible to reconstruct the original fault difference and continue the DFA attack.

However, if the original difference cannot be reconstructed, the corresponding round-key bits may not be recoverable.

---

## Roadmap

Future work includes:

- reconstructing the original fault difference using the SFLL key
- analyzing fault samples corrupted by SFLL perturbations
- improving fault-location identification
- evaluating round-key recovery success rates
- comparing different SFLL-HD parameters
- evaluating the attack under different threat models
- automating experimental statistics
- improving reproducibility of experiments

---

## Experimental Results

Experimental figures are included in this repository, for example:

```text
dfa_success_hd4.png
dfa_success_hd4.pdf
dfa_success_hd4_xor.png
dfa_success_hd4_xor.pdf
```

Further experimental results and analysis will be added as the project progresses.

---

## Reference

Duc-Phong Le, Rongxing Lu, and Ali A. Ghorbani,

**"Improved Fault Analysis on SIMECK Ciphers."**

The DFA implementation in this repository is based on the fault propagation and round-key recovery methodology described in this work.

---

## Disclaimer

This repository is intended for **academic research and educational purposes**.

The implementation is an experimental simulator for studying fault analysis and logic-locking countermeasures in lightweight cryptographic systems.
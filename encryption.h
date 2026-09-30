#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdint.h>

void true_encryption(
    uint16_t keys[],
    uint16_t ciphertext[]
);

void fault_encryption(
    uint16_t keys[],
    uint16_t ciphertext[],
    int fault_round,
    int fault_pos
);

void true_ll_encryption(
    uint16_t keys[],
    uint16_t ciphertext[],
    uint16_t ll,
    int ll_rounds[]
);

void fault_ll_encryption(
    uint16_t keys[],
    uint16_t ciphertext[],
    int fault_round,
    int fault_pos,
    uint16_t ll,
    int ll_rounds[]
);

void true_sfll_encryption(
    uint16_t keys[],
    uint16_t ciphertext[],
    uint16_t sfll
);

void fault_sfll_encryption(
    uint16_t keys[],
    uint16_t ciphertext[],
    int fault_round,
    int fault_pos,
    uint16_t sfll
);

void test_true_sfll_encryption(
    uint16_t keys[],
    uint16_t ciphertext[],
    uint16_t sfll
);

void test_fault_sfll_encryption(
    uint16_t keys[],
    uint16_t ciphertext[],
    int fault_round,
    int fault_pos,
    uint16_t sfll
);

#endif
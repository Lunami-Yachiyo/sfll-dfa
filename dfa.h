#ifndef DFA_H
#define DFA_H

#include <stdint.h>

uint16_t dfa_k31(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r30[],
    uint16_t round_key_r31
);

uint16_t dfa_k30(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r29[],
    uint16_t round_key_r31,
    uint16_t round_key_r30
);

uint16_t dfa_k29(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r28[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    uint16_t round_key_r29
);

uint16_t dfa_k28(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r27[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    uint16_t round_key_r29,
    uint16_t round_key_r28
);

uint16_t dfa_k31_with_sfll(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r30[],
    uint16_t round_key_r31,
    int roundkey_record_r31[],
    int sfll_key[16]
);

uint16_t dfa_k30_with_sfll(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r29[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    int sfll_key[16]
);

uint16_t dfa_k29_with_sfll(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r28[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    uint16_t round_key_r29,
    int sfll_key[16]
);

uint16_t dfa_k28_with_sfll(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r27[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    uint16_t round_key_r29,
    uint16_t round_key_r28,
    int sfll_key[16]
);

#endif
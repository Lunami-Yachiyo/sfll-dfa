#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include "encryption.h"
#include "dfa.h"
#include "decryption.h"

int main(){
    for (int trial=0; trial<10; trial++)
    {

    //STEP 1 INITIALIZATION
    srand((unsigned int)time(NULL) + trial);    
    const uint16_t text32[] = {0x6565, 0x6877};
    const uint16_t key64[] = {0x0100, 0x0908, 0x1110, 0x1918};
    uint16_t true_ciphertext[2] = {0, 0};
    
    uint16_t ll = 0;
    while (ll == 0) ll = rand();
    int ll_rounds[32] = {
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0
    };
    for (int idx=0; idx<32; idx++) ll_rounds[idx] = 1;

    int roundtext_record[6][16] = {-1};
    uint16_t round_key[4] = {0};
    //STEP 1 OVER

    //STEP 2 GET TRUE AND FAULT CIPHERTEXT
    {
    uint16_t plaintext[] = {text32[0], text32[1]};
    uint16_t keys[] = {key64[0], key64[1], key64[2], key64[3]};
    true_ll_encryption(keys, plaintext, ll, ll_rounds);
    true_ciphertext[0] = plaintext[0];
    true_ciphertext[1] = plaintext[1];
    //printf("TRUE CIPHERTEXT = %x %x\n", true_ciphertext[0], true_ciphertext[1]);
    }
    //STEP 2 OVER

    //STEP 3 GET K31
    for (int idx=0; idx<16; idx++)
    {
    uint16_t plaintext[] = {text32[0], text32[1]};
    uint16_t keys[] = {key64[0], key64[1], key64[2], key64[3]};
    fault_ll_encryption(keys, plaintext, 30, idx, ll, ll_rounds);
    uint16_t fault_ciphertext[2] = {plaintext[0], plaintext[1]};
    //printf("FAULT CIPHERTEXT = %x %x\n", fault_ciphertext[0],fault_ciphertext[1]);
    round_key[3] = dfa_k31(true_ciphertext, fault_ciphertext, roundtext_record[3], round_key[3]);    
    }  
    //STEP 3 OVER

    //STEP 4 GET K30
    for (int idx=0; idx<16; idx++)
    {
    uint16_t plaintext[] = {text32[0], text32[1]};
    uint16_t keys[] = {key64[0], key64[1], key64[2], key64[3]};
    fault_ll_encryption(keys, plaintext, 29, idx, ll, ll_rounds);
    uint16_t fault_ciphertext[2] = {plaintext[0], plaintext[1]};
    //printf("FAULT CIPHERTEXT = %x %x\n", fault_ciphertext[0],fault_ciphertext[1]);
    round_key[2] = dfa_k30(true_ciphertext, fault_ciphertext, roundtext_record[2], round_key[3], round_key[2]);    
    } 
    //STEP 4 OVER

    //STEP 5 GET K29
    for (int idx=0; idx<16; idx++)
    {
    uint16_t plaintext[] = {text32[0], text32[1]};
    uint16_t keys[] = {key64[0], key64[1], key64[2], key64[3]};
    fault_ll_encryption(keys, plaintext, 28, idx, ll, ll_rounds);
    uint16_t fault_ciphertext[2] = {plaintext[0], plaintext[1]};
    //printf("FAULT CIPHERTEXT = %x %x\n", fault_ciphertext[0],fault_ciphertext[1]);
    round_key[1] = dfa_k29(true_ciphertext, fault_ciphertext, roundtext_record[1], round_key[3], round_key[2], round_key[1]);    
    } 
    //STEP 5 OVER

    //STEP 6 GET K28
    for (int idx=0; idx<16; idx++)
    {
    uint16_t plaintext[] = {text32[0], text32[1]};
    uint16_t keys[] = {key64[0], key64[1], key64[2], key64[3]};
    fault_ll_encryption(keys, plaintext, 27, idx, ll, ll_rounds);
    uint16_t fault_ciphertext[2] = {plaintext[0], plaintext[1]};
    //printf("FAULT CIPHERTEXT = %x %x\n", fault_ciphertext[0],fault_ciphertext[1]);
    round_key[0] = dfa_k28(true_ciphertext, fault_ciphertext, roundtext_record[0], round_key[3], round_key[2], round_key[1], round_key[0]);    
    }
    //STEP 6 OVER

    //STEP 7 CHECK KEYS
    for (int idx=0; idx<4; idx++){
        printf("K%d = %04x  ", idx+28, round_key[idx]);
    }
    printf("\n");
    //STEP 7 OVER

    //STEP 8 RECOVER MASTER KEY
    //recover_master_key(round_key[0], round_key[1], round_key[2], round_key[3]);
    //recover_master_key(round_key[0] ^ ll, round_key[1] ^ ll, round_key[2] ^ ll, round_key[3]);
    //STEP 8 OVER

    }

    return 0;
}
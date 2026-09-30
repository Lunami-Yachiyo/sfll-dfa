#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include "encryption.h"
#include "dfa.h"
#include "decryption.h"

int main(){
    for (int trial=0; trial<1; trial++)
    {

    //STEP 1 INITIALIZATION
    srand((unsigned int)time(NULL) + trial);    
    const uint16_t text32[] = {0x6565, 0x6877};
    const uint16_t key64[] = {0x0100, 0x0908, 0x1110, 0x1918};
    uint16_t true_ciphertext[2] = {0, 0};
    
    uint16_t sfll = 0;
    while (sfll == 0) sfll = rand();
    sfll = 0x7468;
    //sfll = 0xABD7;
    //sfll = 0xCE0;
    printf("sfll = %x\n", sfll);

    int roundtext_record[6][16] = {0};
    int roundkey_record[4][16];
    for (int idx=0; idx<4; idx++){
        for (int idx2=0; idx2<16; idx2++){
            roundkey_record[idx][idx2] = -1;
        }
    }
    uint16_t round_key[4] = {0};
    int sfll_key[16]; for (int idx=0; idx<16; idx++) sfll_key[idx] = -1;
    //STEP 1 OVER

    //STEP 2 GET TRUE AND FAULT CIPHERTEXT
    {
    uint16_t plaintext[] = {text32[0], text32[1]};
    uint16_t keys[] = {key64[0], key64[1], key64[2], key64[3]};
    test_true_sfll_encryption(keys, plaintext, sfll);
    true_ciphertext[0] = plaintext[0];
    true_ciphertext[1] = plaintext[1];
    printf("TRUE CIPHERTEXT = %x %x\n", true_ciphertext[0], true_ciphertext[1]);
    }
    //STEP 2 OVER

    //STEP 3 GET K31
    for (int idx=0; idx<16; idx++)
    {
    uint16_t plaintext[] = {text32[0], text32[1]};
    uint16_t keys[] = {key64[0], key64[1], key64[2], key64[3]};
    int injection_pos = rand() % 16;
    test_fault_sfll_encryption(keys, plaintext, 30, idx, sfll);
    uint16_t fault_ciphertext[2] = {plaintext[0], plaintext[1]};
    //printf("FAULT CIPHERTEXT = %x %x\n", fault_ciphertext[0],fault_ciphertext[1]);
    round_key[3] = dfa_k31_with_sfll(
        true_ciphertext,
        fault_ciphertext,
        roundtext_record[3],
        round_key[3],
        roundkey_record[3],
        sfll_key
    );    
    }  
    printf("K31 = %4x\n", round_key[3]);
    //STEP 3 OVER
    }

    return 0;
}

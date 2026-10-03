#include <stdio.h>
#include <stdint.h>

#define GETBIT(x, k) (((x) >> ((k) & 15)) & 1u)
#define FLIPBIT(x, k) ((x) ^ (1u << ((k) & 15)))
#define LROT16(x, r) (((x) << (r)) | ((x) >> (16 - (r))))
#define RROT16(x, r) (((x) >> (r)) | ((x) << (16 - (r))))

#define ROUND32(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT16((lft), 5)) ^ LROT16((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

uint16_t round_func(uint16_t text);
int find_fault_pos(uint16_t text);
uint16_t transfer_to_number(int text[16]);
int check_delta(uint16_t delta, int pos);
void print_sfll_key_record(int sfll_key[16]);
void recover_sfll_bits(uint16_t delta_front, uint16_t delta_back, int pos, int sfll_key[16]);
int sfll_recovered(int sfll_key[16]);
int delta_is_legal(uint16_t text);
int find_delta_pattern(uint16_t text);
uint16_t sfll_triggered(uint16_t sfll, uint16_t text, int hd_value);
int hamming_weight(uint16_t text);

int hamming_distance = 8;

uint16_t dfa_k31(
    uint16_t true_ciphertext[], 
    uint16_t fault_ciphertext[],
    int roundtext_record_r30[],
    uint16_t round_key_r31){

    uint16_t delta[] = {
        0, 0, 0, 0,
        true_ciphertext[1] ^ fault_ciphertext[1],
        true_ciphertext[0] ^ fault_ciphertext[0]
    };
    delta[3] = delta[5] ^ round_func(true_ciphertext[1]) ^ round_func(fault_ciphertext[1]);

    //printf("%016b %016b %016b\n", delta[3], delta[4], delta[5]);

    int pos = find_fault_pos(delta[3]);
    //printf("%d\n", pos);
    if (pos != -1){
        int tmp = GETBIT(delta[4], pos);
        roundtext_record_r30[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[4], pos+5);
        roundtext_record_r30[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r30);
        round_key_r31 = roundtext ^ round_func(true_ciphertext[1]) ^ true_ciphertext[0];

        //printf("%x %x\n", roundtext, round_key_r31);
    }

    return round_key_r31;
}

uint16_t dfa_k30(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r29[],
    uint16_t round_key_r31,
    uint16_t round_key_r30){
    
    uint16_t delta[] = {
        0, 0, 0, 0,
        true_ciphertext[1] ^ fault_ciphertext[1],
        true_ciphertext[0] ^ fault_ciphertext[0]
    };
    delta[3] = delta[5] ^ round_func(true_ciphertext[1]) ^ round_func(fault_ciphertext[1]);
    
    uint16_t true_roundtext_r30 = true_ciphertext[0] ^ round_key_r31 ^ round_func(true_ciphertext[1]);
    uint16_t fault_roundtext_r30 = fault_ciphertext[0] ^ round_key_r31 ^ round_func(fault_ciphertext[1]);
    delta[3] = true_roundtext_r30 ^ fault_roundtext_r30;
    delta[2] = delta[4] ^ round_func(true_roundtext_r30) ^ round_func(fault_roundtext_r30);

    int pos = find_fault_pos(delta[2]);
    //printf("%d\n", pos);
    //printf("%016b %016b %016b %016b\n", delta[2], delta[3], delta[4], delta[5]);
    if (pos != -1){
        int tmp = GETBIT(delta[3], pos);
        roundtext_record_r29[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[3], pos+5);
        roundtext_record_r29[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r29);
        round_key_r30 = roundtext ^ round_func(true_roundtext_r30) ^ true_ciphertext[1];

        //printf("%x %x\n", roundtext, round_key_r30);
    }

    return round_key_r30;
}

uint16_t dfa_k29(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r28[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    uint16_t round_key_r29){

    uint16_t delta[] = {
        0, 0, 0, 0,
        true_ciphertext[1] ^ fault_ciphertext[1],
        true_ciphertext[0] ^ fault_ciphertext[0]
    };
    delta[3] = delta[5] ^ round_func(true_ciphertext[1]) ^ round_func(fault_ciphertext[1]);
    
    uint16_t true_roundtext_r30 = true_ciphertext[0] ^ round_key_r31 ^ round_func(true_ciphertext[1]);
    uint16_t fault_roundtext_r30 = fault_ciphertext[0] ^ round_key_r31 ^ round_func(fault_ciphertext[1]);
    delta[3] = true_roundtext_r30 ^ fault_roundtext_r30;
    delta[2] = delta[4] ^ round_func(true_roundtext_r30) ^ round_func(fault_roundtext_r30);

    uint16_t true_roundtext_r29 = true_ciphertext[1] ^ round_key_r30 ^ round_func(true_roundtext_r30);
    uint16_t fault_roundtext_r29 = fault_ciphertext[1] ^ round_key_r30 ^ round_func(fault_roundtext_r30);
    delta[2] = true_roundtext_r29 ^ fault_roundtext_r29;
    delta[1] = delta[3] ^ round_func(true_roundtext_r29) ^ round_func(fault_roundtext_r29);

    int pos = find_fault_pos(delta[1]);
    //printf("%d\n", pos);
    //printf("%016b %016b %016b %016b\n", delta[2], delta[3], delta[4], delta[5]);
    if (pos != -1){
        int tmp = GETBIT(delta[2], pos);
        roundtext_record_r28[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[2], pos+5);
        roundtext_record_r28[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r28);
        round_key_r29 = roundtext ^ round_func(true_roundtext_r29) ^ true_roundtext_r30;

        //printf("%x %x\n", roundtext, round_key_r29);
    }

    return round_key_r29;
}

uint16_t dfa_k28(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r27[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    uint16_t round_key_r29,
    uint16_t round_key_r28){

    uint16_t delta[] = {
        0, 0, 0, 0,
        true_ciphertext[1] ^ fault_ciphertext[1],
        true_ciphertext[0] ^ fault_ciphertext[0]
    };
    delta[3] = delta[5] ^ round_func(true_ciphertext[1]) ^ round_func(fault_ciphertext[1]);
    
    uint16_t true_roundtext_r30 = true_ciphertext[0] ^ round_key_r31 ^ round_func(true_ciphertext[1]);
    uint16_t fault_roundtext_r30 = fault_ciphertext[0] ^ round_key_r31 ^ round_func(fault_ciphertext[1]);
    delta[3] = true_roundtext_r30 ^ fault_roundtext_r30;
    delta[2] = delta[4] ^ round_func(true_roundtext_r30) ^ round_func(fault_roundtext_r30);

    uint16_t true_roundtext_r29 = true_ciphertext[1] ^ round_key_r30 ^ round_func(true_roundtext_r30);
    uint16_t fault_roundtext_r29 = fault_ciphertext[1] ^ round_key_r30 ^ round_func(fault_roundtext_r30);
    delta[2] = true_roundtext_r29 ^ fault_roundtext_r29;
    delta[1] = delta[3] ^ round_func(true_roundtext_r29) ^ round_func(fault_roundtext_r29);

    uint16_t true_roundtext_r28 = true_roundtext_r30 ^ round_key_r29 ^ round_func(true_roundtext_r29);
    uint16_t fault_roundtext_r28 = fault_roundtext_r30 ^ round_key_r29 ^ round_func(fault_roundtext_r29);
    delta[1] = true_roundtext_r28 ^ fault_roundtext_r28;
    delta[0] = delta[2] ^ round_func(true_roundtext_r28) ^ round_func(fault_roundtext_r28);

    int pos = find_fault_pos(delta[0]);
    //printf("%d\n", pos);
    //printf("%016b %016b %016b %016b\n", delta[2], delta[3], delta[4], delta[5]);
    if (pos != -1){
        int tmp = GETBIT(delta[1], pos);
        roundtext_record_r27[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[1], pos+5);
        roundtext_record_r27[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r27);
        round_key_r28 = roundtext ^ round_func(true_roundtext_r28) ^ true_roundtext_r29;

        //printf("%x %x\n", roundtext, round_key_r28);
    }

    return round_key_r28;
}

uint16_t dfa_k31_with_sfll(
    uint16_t true_ciphertext[], 
    uint16_t fault_ciphertext[],
    int roundtext_record_r30[],
    uint16_t round_key_r31,
    int roundkey_record_r31[],
    int sfll_key[16]){

    uint16_t delta[] = {
        0, 0, 0, 0,
        true_ciphertext[1] ^ fault_ciphertext[1],
        true_ciphertext[0] ^ fault_ciphertext[0]
    };
    delta[3] = delta[5] ^ round_func(true_ciphertext[1]) ^ round_func(fault_ciphertext[1]);

    //printf("%016b %016b %016b\n", delta[3], delta[4], delta[5]);

    int pos = find_fault_pos(delta[3]);
    //printf("%d\n", pos);
    //printf("%016b %016b %016b\n", delta[3], delta[4], delta[5]);

    if ((pos != -1) && (check_delta(delta[4], pos) == 0)){
        int tmp = GETBIT(delta[4], pos);
        roundtext_record_r30[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[4], pos+5);
        roundtext_record_r30[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r30);
        round_key_r31 = roundtext ^ round_func(true_ciphertext[1]) ^ true_ciphertext[0];

        //printf("%x %x\n", roundtext, round_key_r31);
    } else if (sfll_recovered(sfll_key) == 1) {
        delta[4] = delta[4] ^ transfer_to_number(sfll_key);
        int tmp = GETBIT(delta[4], pos);
        roundtext_record_r30[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[4], pos+5);
        roundtext_record_r30[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r30);
        round_key_r31 = roundtext ^ round_func(true_ciphertext[1]) ^ true_ciphertext[0];

    } else {
        recover_sfll_bits(delta[3], delta[4], pos, sfll_key);
        //print_sfll_key_record(sfll_key);
    }

    return round_key_r31;
}

uint16_t dfa_k30_with_sfll(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r29[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    int sfll_key[16]){

    uint16_t delta[] = {
        0, 0, 0, 0,
        true_ciphertext[1] ^ fault_ciphertext[1],
        true_ciphertext[0] ^ fault_ciphertext[0]
    };
    
    uint16_t true_roundtext_r30 = true_ciphertext[0] ^ round_key_r31 ^ round_func(true_ciphertext[1]);
    uint16_t fault_roundtext_r30 = fault_ciphertext[0] ^ round_key_r31 ^ round_func(fault_ciphertext[1]);

    //RECOVER REAL STATES
    /*
    uint16_t real_true_ciphertext = true_ciphertext[1] ^
        sfll_triggered(true_ciphertext[1], transfer_to_number(sfll_key), hamming_distance);
    uint16_t real_fault_ciphertext = fault_ciphertext[1] ^ 
        sfll_triggered(fault_ciphertext[1], transfer_to_number(sfll_key), hamming_distance);
    uint16_t real_true_roundtext_r30 = true_ciphertext[0] ^ round_key_r31 ^ round_func(real_true_ciphertext);
    uint16_t real_fault_roundtext_r30 = fault_ciphertext[0] ^ round_key_r31 ^ round_func(real_fault_ciphertext);
    
    delta[4] = real_true_ciphertext ^ real_fault_ciphertext;
    delta[3] = real_true_roundtext_r30 ^ real_fault_roundtext_r30;
    delta[2] = delta[4] ^ round_func(real_true_roundtext_r30) ^ round_func(real_fault_roundtext_r30);
    */

    delta[4] = true_ciphertext[1] ^ fault_ciphertext[1];
    delta[3] = true_roundtext_r30 ^ fault_roundtext_r30;
    delta[2] = delta[4] ^ round_func(true_roundtext_r30) ^ round_func(fault_roundtext_r30);

    int pos = find_fault_pos(delta[2]);
    
    
    //printf("POS = %d\n", pos);
    
    /*
    printf("TRUE:                   %016b %016b %016b\n", real_true_roundtext_r30, real_true_ciphertext, true_ciphertext[0]);
    printf("FAULT:                  %016b %016b %016b\n", real_fault_roundtext_r30, real_fault_ciphertext, fault_ciphertext[0]);
    printf("DELTA: %016b %016b %016b %016b\n", delta[2], delta[3], delta[4], delta[5]);
    printf("ORIGINAL = %016b %016b\n", true_ciphertext[1], fault_ciphertext[1]);
    printf("SFLL =     %016b %016b\n", transfer_to_number(sfll_key), transfer_to_number(sfll_key));
    printf("SUM =      %016b %016b\n", true_ciphertext[1] ^ transfer_to_number(sfll_key), fault_ciphertext[1] ^ transfer_to_number(sfll_key));
    */
    

    //WHEN DELTA2 AND DELTA3 ARE BOTH LEGAL
    if ((pos != -1) && (check_delta(delta[3], pos) == 0)) {
        int tmp = GETBIT(delta[3], pos);
        roundtext_record_r29[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[3], pos+5);
        roundtext_record_r29[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r29);
        round_key_r30 = roundtext ^ round_func(true_roundtext_r30) ^ true_ciphertext[1];

        //printf("%x %x\n", roundtext, round_key_r30);
    }

    //WHEN DELTA2 IS NOT LEGAL
    if ((pos == -1) && (sfll_recovered(sfll_key) == 1)) {
        delta[2] = delta[2] ^ transfer_to_number(sfll_key);
        pos = find_fault_pos(delta[2]);
        //printf("REAL POS = %d\n", pos);
        //printf("ORINIGAL = %016b %016b %016b %016b\n",delta[2], delta[3], delta[4], delta[5]);

        //WHEN DELTA3 IS NOT LEGAL
        if (check_delta(delta[3], pos) == -1) {
            delta[3] = delta[3] ^ transfer_to_number(sfll_key);
        }
        int tmp = GETBIT(delta[3], pos);
        roundtext_record_r29[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[3], pos+5);
        roundtext_record_r29[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r29);
        round_key_r30 = roundtext ^ round_func(true_roundtext_r30) ^ true_ciphertext[1];

        //printf("%x %x\n", roundtext, round_key_r30); 
    }

    //WHEN SFLL KEY IS NOT RECOVERED
    if ((pos != -1) && (check_delta(delta[3], pos) == -1) && (sfll_recovered(sfll_key) == 0)){
        recover_sfll_bits(delta[2], delta[3], pos, sfll_key);
        //print_sfll_key_record(sfll_key);   
    }
    return round_key_r30;
}

uint16_t dfa_k29_with_sfll(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r28[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    uint16_t round_key_r29,
    int sfll_key[16]){

    uint16_t delta[] = {
        0, 0, 0, 0,
        true_ciphertext[1] ^ fault_ciphertext[1],
        true_ciphertext[0] ^ fault_ciphertext[0]
    };
    delta[3] = delta[5] ^ round_func(true_ciphertext[1]) ^ round_func(fault_ciphertext[1]);
    
    uint16_t true_roundtext_r30 = true_ciphertext[0] ^ round_key_r31 ^ round_func(true_ciphertext[1]);
    uint16_t fault_roundtext_r30 = fault_ciphertext[0] ^ round_key_r31 ^ round_func(fault_ciphertext[1]);
    delta[3] = true_roundtext_r30 ^ fault_roundtext_r30;
    delta[2] = delta[4] ^ round_func(true_roundtext_r30) ^ round_func(fault_roundtext_r30);

    uint16_t true_roundtext_r29 = true_ciphertext[1] ^ round_key_r30 ^ round_func(true_roundtext_r30);
    uint16_t fault_roundtext_r29 = fault_ciphertext[1] ^ round_key_r30 ^ round_func(fault_roundtext_r30);
    delta[2] = true_roundtext_r29 ^ fault_roundtext_r29;
    delta[1] = delta[3] ^ round_func(true_roundtext_r29) ^ round_func(fault_roundtext_r29);

    int pos = find_fault_pos(delta[1]);
    //printf("%d\n", pos);
    
    /*
    printf("ORINIGAL = %016b %016b %016b %016b %016b\n",delta[1], delta[2], delta[3], delta[4], delta[5]);
    printf("NEW =      %016b %016b %016b %016b %016b\n",
        delta[1] ^ transfer_to_number(sfll_key),
        delta[2] ^ transfer_to_number(sfll_key),
        delta[3] ^ transfer_to_number(sfll_key),
        delta[4] ^ transfer_to_number(sfll_key),
        delta[5] ^ transfer_to_number(sfll_key)
    );
    */

    //WHEN DELTA1 AND DELTA2 ARE BOTH LEGAL
    if ((pos != -1) && (check_delta(delta[2], pos) == 0)){
        int tmp = GETBIT(delta[2], pos);
        roundtext_record_r28[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[2], pos+5);
        roundtext_record_r28[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r28);
        round_key_r29 = roundtext ^ round_func(true_roundtext_r29) ^ true_roundtext_r30;

        //printf("%x %x\n", roundtext, round_key_r29);
    }

    //WHEN DELTA1 IS NOT LEGAL
    if ((pos == -1) && (sfll_recovered(sfll_key) == 1)) {
        delta[1] = delta[1] ^ transfer_to_number(sfll_key);
        pos = find_fault_pos(delta[1]);
    }

    //WHEN DELTA2 IS NOT LEGAL
    if ((find_delta_pattern(delta[2]) == -1) && (sfll_recovered(sfll_key) == 1)) {
        delta[2] = delta[2] ^ transfer_to_number(sfll_key);
        pos = find_delta_pattern(delta[2]);
        //printf("*******************%d %016b\n", pos, delta[2]);
    }

    if (sfll_recovered(sfll_key) == 1){
        int tmp = GETBIT(delta[2], pos);
        roundtext_record_r28[(pos+11)%16] = tmp;
        tmp = GETBIT(delta[2], pos+5);
        roundtext_record_r28[(pos+5)%16] = tmp;
        uint16_t roundtext = transfer_to_number(roundtext_record_r28);
        round_key_r29 = roundtext ^ round_func(true_roundtext_r29) ^ true_roundtext_r30;

        //printf("%x %x\n", roundtext, round_key_r29);
    }

    return round_key_r29;
}

uint16_t dfa_k28_with_sfll(
    uint16_t true_ciphertext[],
    uint16_t fault_ciphertext[],
    int roundtext_record_r27[],
    uint16_t round_key_r31,
    uint16_t round_key_r30,
    uint16_t round_key_r29,
    uint16_t round_key_r28,
    int sfll_key[16]){

    //TEST
    //round_key_r30 ^= transfer_to_number(sfll_key);

    uint16_t delta[] = {
        0, 0, 0, 0,
        true_ciphertext[1] ^ fault_ciphertext[1],
        true_ciphertext[0] ^ fault_ciphertext[0]
    };
    delta[3] = delta[5] ^ round_func(true_ciphertext[1]) ^ round_func(fault_ciphertext[1]);
    
    uint16_t true_roundtext_r30 = true_ciphertext[0] ^ round_key_r31 ^ round_func(true_ciphertext[1]);
    uint16_t fault_roundtext_r30 = fault_ciphertext[0] ^ round_key_r31 ^ round_func(fault_ciphertext[1]);
    delta[3] = true_roundtext_r30 ^ fault_roundtext_r30;
    delta[2] = delta[4] ^ round_func(true_roundtext_r30) ^ round_func(fault_roundtext_r30);

    uint16_t true_roundtext_r29 = true_ciphertext[1] ^ round_key_r30 ^ round_func(true_roundtext_r30);
    uint16_t fault_roundtext_r29 = fault_ciphertext[1] ^ round_key_r30 ^ round_func(fault_roundtext_r30);
    delta[2] = true_roundtext_r29 ^ fault_roundtext_r29;
    delta[1] = delta[3] ^ round_func(true_roundtext_r29) ^ round_func(fault_roundtext_r29);

    uint16_t true_roundtext_r28 = true_roundtext_r30 ^ round_key_r29 ^ round_func(true_roundtext_r29);
    uint16_t fault_roundtext_r28 = fault_roundtext_r30 ^ round_key_r29 ^ round_func(fault_roundtext_r29);
    delta[1] = true_roundtext_r28 ^ fault_roundtext_r28;
    delta[0] = delta[2] ^ round_func(true_roundtext_r28) ^ round_func(fault_roundtext_r28);

    int pos = find_fault_pos(delta[0]);
    /*
    printf("%d\n", pos);
    printf("ORINIGAL =%016b %016b %016b %016b %016b %016b\n", delta[0], delta[1], delta[2], delta[3], delta[4], delta[5]);
    printf("NEW = %016b %016b %016b %016b %016b %016b\n",
        delta[0] ^ transfer_to_number(sfll_key),
        delta[1] ^ transfer_to_number(sfll_key),
        delta[2] ^ transfer_to_number(sfll_key),
        delta[3] ^ transfer_to_number(sfll_key),
        delta[4] ^ transfer_to_number(sfll_key),
        delta[5] ^ transfer_to_number(sfll_key)
    );
    */
    
    if (pos == -1) {
        delta[0] = delta[0] ^ transfer_to_number(sfll_key);
        pos = find_fault_pos(delta[0]);
        //printf("%d\n", pos);
        //printf("%016b %016b %016b %016b %016b %016b\n", delta[0], delta[1], delta[2], delta[3], delta[4], delta[5]);
    }

    if ((pos != -1) && (sfll_recovered(sfll_key) == 1)) {
        if (check_delta(delta[1], pos) == -1){
            delta[1] = delta[1] ^ transfer_to_number(sfll_key);
            //printf("%d\n", pos);
            //printf("%016b %016b %016b %016b %016b %016b\n", delta[0], delta[1], delta[2], delta[3], delta[4], delta[5]);
        }
        
        uint16_t roundtext = 0;
        if (pos != 1){
            int tmp = GETBIT(delta[1], pos);
            roundtext_record_r27[(pos+11)%16] = tmp;
            tmp = GETBIT(delta[1], pos+5);
            roundtext_record_r27[(pos+5)%16] = tmp;
            uint16_t roundtext = transfer_to_number(roundtext_record_r27);
            round_key_r28 = roundtext ^ round_func(true_roundtext_r28) ^ true_roundtext_r29;
        }
        //printf("%x %x\n", roundtext, round_key_r28);
    } else if (pos != -1) {
        recover_sfll_bits(delta[0], delta[1], pos, sfll_key);
        //print_sfll_key_record(sfll_key);   
    }
    
    return round_key_r28;
}

uint16_t round_func(uint16_t text){
    text = (LROT16(text, 5) & text) ^ LROT16(text, 1);
    return text;
}

int find_fault_pos(uint16_t text){
    int temp = -1;

    for (int pos = 0; pos < 16; pos++) {
        if (text & (1u << pos)) {
            if  (temp == -1) {
                temp = pos;
            } else {
                return -1;
            }
        } 
    }

    return temp;
}

uint16_t transfer_to_number(int text[16])
{
    uint16_t result = 0;

    for (int i = 0; i < 16; i++) {
        if (text[i]) {
            result |= (1u << i);
        }
    }

    return result;
}

int check_delta(uint16_t delta, int pos){
    if (pos != -1) {
        for (int idx = 0; idx < 16; idx++) {
            if (idx == pos || idx == (pos + 5) % 16) {
                continue;
            }

            if ((idx == (pos + 1) % 16) && (GETBIT(delta, idx) == 0)) {
                return -1;
            }

            if ((idx != (pos + 1) % 16) && (GETBIT(delta, idx) == 1)) {
                return -1;
            }
            
        }
        return 0;
    }

    return -1;
}

void print_sfll_key_record(int sfll_key[16]){
    printf("sfll = ");
    for (int idx=15; idx>=0; idx--){
        if (sfll_key[idx] == -1) {
            printf("*");
        } else {
            printf("%d", sfll_key[idx]);
        }
    }

    printf("\n");
}

void recover_sfll_bits(uint16_t delta_front, uint16_t delta_back, int pos, int sfll_key[16]){
    uint16_t temp = delta_back;

    for (int idx=0; idx<16; idx++){
        if ((idx != (pos + 5) % 16) && (idx != pos)){
            if (idx == (pos + 1) % 16){
                sfll_key[idx] = !GETBIT(temp, idx);
            } else {
                sfll_key[idx] = GETBIT(temp, idx);
            }
        }
    }

    //printf("%x\n", temp);
}

int sfll_recovered(int sfll_key[16]){
    for (int idx=0; idx<16; idx++){
        if (sfll_key[idx] == -1){
            return 0;
        }
    }

    return 1;
}

int delta_is_legal(uint16_t text){
    for (int idx=0; idx<16; idx++){
        if (GETBIT(text, idx) == 1) {
            printf("%x\n", text);
        }
    }

    return -1;
}

int find_delta_pattern(uint16_t text){
    for (int idx=0; idx<16; idx++){
        if (check_delta(text, idx) == 0){
            return idx;
        }
    }

    return -1;
}

uint16_t sfll_triggered(uint16_t text, uint16_t sfll, int hd_value){
    int temp_hd = hamming_weight(text ^ sfll);
    //printf("%d\n", temp_hd);
    if (temp_hd == hd_value){
        return sfll;
    } 

    return 0;
}

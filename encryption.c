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

const int NUM_ROUNDS = 32;
const int HAMMING_VALUE = 4;
int hamming_weight(uint16_t text);
int hamming_distance_uint16(uint16_t a, uint16_t b);

void true_encryption(uint16_t keys[], uint16_t ciphertext[]){
    int idx;
    uint16_t temp;
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;
    
    //32 ROUNDS ENCRYPTION
    for (idx = 0; idx < NUM_ROUNDS; idx++) {
        ROUND32(
                keys[0],
                ciphertext[0],
                ciphertext[1],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
                keys[1],
                keys[0],
                temp
        );

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;        
    }
    //32 ROUNDS ENCRYPTION OVER
}

void fault_encryption(uint16_t keys[], uint16_t ciphertext[], int fault_round, int fault_pos){
    int idx;
    uint16_t temp;
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;
    
    //32 ROUNDS ENCRYPTION
    for (idx = 0; idx < NUM_ROUNDS; idx++) {
        if (idx == fault_round){
            ciphertext[0] = FLIPBIT(ciphertext[0], fault_pos);
        }
        ROUND32(
                keys[0],
                ciphertext[0],
                ciphertext[1],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
                keys[1],
                keys[0],
                temp
        );

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;        
    }
    //32 ROUNDS ENCRYPTION OVER
}

void true_ll_encryption(uint16_t keys[], uint16_t ciphertext[], uint16_t ll, int ll_rounds[]){
    int idx;
    uint16_t temp;
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;
    
    //32 ROUNDS ENCRYPTION
    for (idx = 0; idx < NUM_ROUNDS; idx++) {
        if (ll_rounds[idx] == 1){
            ciphertext[0] = ciphertext[0] ^ ll;
        }
        ROUND32(
                keys[0],
                ciphertext[0],
                ciphertext[1],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
                keys[1],
                keys[0],
                temp
        );

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;        
    }
    //32 ROUNDS ENCRYPTION OVER
}

void fault_ll_encryption(uint16_t keys[], uint16_t ciphertext[], int fault_round, int fault_pos, uint16_t ll, int ll_rounds[]){
    int idx;
    uint16_t temp;
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;
    
    //32 ROUNDS ENCRYPTION
    for (idx = 0; idx < NUM_ROUNDS; idx++) {
        if (ll_rounds[idx] == 1){
            ciphertext[0] = ciphertext[0] ^ ll;
        }
        if (idx == fault_round){
            ciphertext[0] = FLIPBIT(ciphertext[0], fault_pos);
        }
        ROUND32(
                keys[0],
                ciphertext[0],
                ciphertext[1],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
                keys[1],
                keys[0],
                temp
        );

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;        
    }
    //32 ROUNDS ENCRYPTION OVER
}

void true_sfll_encryption(uint16_t keys[], uint16_t ciphertext[], uint16_t sfll){
    int idx;
    uint16_t temp;
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;
    
    //32 ROUNDS ENCRYPTION
    for (idx = 0; idx < NUM_ROUNDS; idx++) {
        //printf("%02d before = %016b", idx, ciphertext[0]);
        if (hamming_weight(ciphertext[0]) == HAMMING_VALUE){
            ciphertext[0] = ciphertext[0] ^ sfll;
        }
        //printf("after = %016b\n", ciphertext[0]);

        ROUND32(
                keys[0],
                ciphertext[0],
                ciphertext[1],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
                keys[1],
                keys[0],
                temp
        );

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;    
        //printf("%04x\n", keys[0]);   
    }
    //32 ROUNDS ENCRYPTION OVER
}

void fault_sfll_encryption(uint16_t keys[], uint16_t ciphertext[], int fault_round, int fault_pos, uint16_t sfll){
    int idx;
    uint16_t temp;
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;
    
    //32 ROUNDS ENCRYPTION
    for (idx = 0; idx < NUM_ROUNDS; idx++) {
        //printf("%02d before = %016b", idx, ciphertext[0]);
        if (hamming_weight(ciphertext[0]) == HAMMING_VALUE){
            ciphertext[0] = ciphertext[0] ^ sfll;
        }
        //printf("after = %016b\n", ciphertext[0]);

        if (idx == fault_round){
            ciphertext[0] = FLIPBIT(ciphertext[0], fault_pos);
        }

        ROUND32(
                keys[0],
                ciphertext[0],
                ciphertext[1],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
                keys[1],
                keys[0],
                temp
        );

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;        
    }
    //32 ROUNDS ENCRYPTION OVER
    //printf("FAULT CIPHERTEXT = %x %x\n", ciphertext[0], ciphertext[1]);
}

int hamming_weight(uint16_t text){
    int hw = 0;

    while (text != 0){
        hw += text & 1;
        text >>= 1;
    }

    return hw;
}

void test_true_sfll_encryption(uint16_t keys[], uint16_t ciphertext[], uint16_t sfll){
    int idx;
    uint16_t temp;
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;
    
    //32 ROUNDS ENCRYPTION
    for (idx = 0; idx < NUM_ROUNDS; idx++) {
        printf("%02d %x %x", idx, ciphertext[0], ciphertext[1]);
        if (hamming_distance_uint16(ciphertext[0], sfll) == HAMMING_VALUE){
            ciphertext[0] = ciphertext[0] ^ sfll;
            printf(" sfll %x %x", ciphertext[0], ciphertext[1]);
        }
        printf("\n");

        ROUND32(
                keys[0],
                ciphertext[0],
                ciphertext[1],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
                keys[1],
                keys[0],
                temp
        );

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;        
    }
    //32 ROUNDS ENCRYPTION OVER
}

void test_fault_sfll_encryption(uint16_t keys[], uint16_t ciphertext[], int fault_round, int fault_pos, uint16_t sfll){
    int idx;
    uint16_t temp;
    uint16_t constant = 0xFFFC;
    uint32_t sequence = 0x9A42BB1F;
    
    //32 ROUNDS ENCRYPTION
    for (idx = 0; idx < NUM_ROUNDS; idx++) {
        printf("%02d %x %x", idx, ciphertext[0], ciphertext[1]);
        if (hamming_distance_uint16(ciphertext[0], sfll) == HAMMING_VALUE){
            ciphertext[0] = ciphertext[0] ^ sfll;
            printf(" sfll %x %x", ciphertext[0], ciphertext[1]);
        }
        printf("\n");

        if (idx == fault_round){
            ciphertext[0] = FLIPBIT(ciphertext[0], fault_pos);
        }

        ROUND32(
                keys[0],
                ciphertext[0],
                ciphertext[1],
                temp
        );

        constant &= 0xFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND32(
                constant,
                keys[1],
                keys[0],
                temp
        );

        temp = keys[1];
        keys[1] = keys[2];
        keys[2] = keys[3];
        keys[3] = temp;        
    }
    //32 ROUNDS ENCRYPTION OVER
}

int hamming_distance_uint16(uint16_t a, uint16_t b)
{
    uint16_t x = a ^ b;
    int distance = 0;

    while (x) {
        distance += x & 1;
        x >>= 1;
    }

    return distance;
}
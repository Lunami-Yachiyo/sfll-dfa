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

void recover_master_key(
    uint16_t k28,
    uint16_t k29,
    uint16_t k30,
    uint16_t k31)
{
    uint16_t round_keys[32];
    uint16_t constants[32];

    uint32_t sequence = 0x9A42BB1F;

    for (int i = 0; i < 32; i++) {
        uint16_t constant = 0xFFFC;

        constant |= sequence & 1;
        sequence >>= 1;

        constants[i] = constant;
    }

    round_keys[28] = k28;
    round_keys[29] = k29;
    round_keys[30] = k30;
    round_keys[31] = k31;

    for (int i = 27; i >= 0; i--) {
        round_keys[i] =
            round_keys[i + 4]
            ^ round_func(round_keys[i + 1])
            ^ constants[i];
    }

    printf("Master key: ");

    printf("%04x %04x %04x %04x\n",
        round_keys[0],
        round_keys[1],
        round_keys[2],
        round_keys[3]);
}

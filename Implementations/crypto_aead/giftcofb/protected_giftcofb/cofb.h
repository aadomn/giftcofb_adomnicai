#ifndef GIFT_COFB_H_
#define GIFT_COFB_H_

#include <stdint.h>

#define TAG_SIZE        16
#define KEY_SIZE        16
#define COFB_ENCRYPT    1
#define COFB_DECRYPT    0

typedef struct masked_rkey {
    uint32_t rkey[80];
    uint32_t rkey_mask[80];
} masked_rkey;

#define XOR_BLOCK(x, y, z) ({       \
    (x)[0] = (y)[0] ^ (z)[0];       \
    (x)[1] = (y)[1] ^ (z)[1];       \
    (x)[2] = (y)[2] ^ (z)[2];       \
    (x)[3] = (y)[3] ^ (z)[3];       \
})

#define XOR_TOP_BAR_BLOCK(x, y) ({  \
    (x)[0] ^= (y)[0];               \
    (x)[1] ^= (y)[1];               \
})

#endif // GIFT_COFB_H_
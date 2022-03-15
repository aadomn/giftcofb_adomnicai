#ifndef GIFT128_H_
#define GIFT128_H_

#include <stdint.h>

#define KEY_SIZE    		16
#define GIFT128_BLOCK_SIZE  16

extern void gift128_keyschedule(const uint8_t* key, uint32_t* rkey, const uint8_t* key_m);
extern void giftb128_encrypt_block(uint8_t* out_block, const uint32_t* rkey, const uint8_t* in_block);

#endif  // GIFT128_H_
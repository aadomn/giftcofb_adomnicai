/**
 * GIFT-COFB ARMv7-M implementation (w/ 1st-order masking countermeasure)
 * following the API defined in the Call for Protected Software Implementations
 * of Finalists in the NIST Lightweight Cryptography Standardization Process
 * by George Mason Univeristy: https://cryptography.gmu.edu/athena/LWC/Call_for
 * _Protected_Software_Implementations.pdf
 * 
 * @author      Alexandre Adomnicai
 *              alex.adomnicai@gmail.com
 * 
 * @date        March 2022
 */
#include <string.h>
#include <stdint.h>
#include "cofb.h"
#include "giftb128.h"
#include "randombytes.h"
#include "crypto_aead_shared.h"

/**
 * COFB mode related internal functions.
 */
static inline void padding(uint32_t* d, const uint32_t* s, const uint32_t no_of_bytes){
    int i;
    if (no_of_bytes == 0) {
        d[0] = 0x00000080; // little-endian
        d[1] = 0x00000000;
        d[2] = 0x00000000;
        d[3] = 0x00000000;
    }
    else if (no_of_bytes < GIFT128_BLOCK_SIZE) {
        for (i = 0; i < no_of_bytes/4+1; i++)
            d[i] = s[i];
        d[i-1] &= ~(0xffffffffL << (no_of_bytes % 4)*8);
        d[i-1] |= 0x00000080L << (no_of_bytes % 4)*8;
        for (; i < 4; i++)
            d[i] = 0x00000000;
    }
    else {
        d[0] = s[0];
        d[1] = s[1];
        d[2] = s[2];
        d[3] = s[3];
    }
}

static void xor_block(uint8_t* d, const uint8_t* s1, const uint8_t* s2, unsigned no_of_bytes) {
    unsigned i;
    for (i=0; i<no_of_bytes; i++)
        d[i] = s1[i] ^ s2[i];
}

static inline void double_half_block(uint32_t* x) {
    uint32_t tmp0;
    tmp0 = (x)[0];
    (x)[0] = (((x)[0] & 0x7f7f7f7f) << 1) | (((x)[0] & 0x80808080) >> 15);
    (x)[0] |= ((x)[1] & 0x80808080) << 17;
    (x)[1] = (((x)[1] & 0x7f7f7f7f) << 1) | (((x)[1] & 0x80808080) >> 15);
    (x)[1] ^= (((tmp0 >> 7) & 1) * 27) << 24;
}

static inline void triple_half_block(uint32_t* x) {
    uint32_t tmp0, tmp1;
    tmp0 = (x)[0];
    tmp1 = (x)[1];
    (x)[0] = (((x)[0] & 0x7f7f7f7f) << 1) | (((x)[0] & 0x80808080) >> 15);
    (x)[0] |= ((x)[1] & 0x80808080) << 17;
    (x)[1] = (((x)[1] & 0x7f7f7f7f) << 1) | (((x)[1] & 0x80808080) >> 15);
    (x)[1] ^= (((tmp0 >> 7) & 1) * 27) << 24;
    (x)[0] ^= tmp0;
    (x)[1] ^= tmp1;
}

static inline void g(uint32_t *x) {
    uint32_t tmp0, tmp1;
    tmp0 = (x)[0];
    tmp1 = (x)[1];
    (x)[0] = (x)[2];
    (x)[1] = (x)[3];
    (x)[2] = ((tmp0 & 0x7f7f7f7f) << 1) | ((tmp0 & 0x80808080) >> 15);
    (x)[2] |= ((tmp1 & 0x80808080) << 17);
    (x)[3] = ((tmp1 & 0x7f7f7f7f) << 1) | ((tmp1 & 0x80808080) >> 15);
    (x)[3] |= ((tmp0 & 0x80808080) << 17);
}

static inline void rho1(uint8_t* d, uint8_t* y, const uint8_t* m, uint8_t n)
{
    g((uint32_t *)y);
    padding((uint32_t *)d, (uint32_t *)m, n);
    xor_block(d, d, y, 16);
}

static inline void rho(uint8_t* y, const uint8_t* m, uint8_t* x, uint8_t* c, unsigned long long n)
{
    xor_block(c, y, m, n);
    rho1(x, y, m, n);
}

static inline void rho_prime(uint8_t* y, const uint8_t*c, uint8_t* x, uint8_t* m, unsigned long long n)
{
    xor_block(m, y, c, n);
    rho1(x, y, m, n);
}

/****************************************************************************
* Constant-time implementation of the GIFT-COFB authenticated cipher based on
* fixsliced GIFTb-128. Encryption/decryption is handled by the same function,
* depending on the 'mode' parameter (1/0).
****************************************************************************/
int giftcofb_crypt(
    uint8_t* out,
    const uint8_t* key,
    const uint8_t* key_m,
    const uint8_t* nonce,
    const uint8_t* ad, unsigned long long ad_len,
    const uint8_t* in, unsigned long long in_len,
    const int mode)
{
    int i, ret;
    uint32_t offset[GIFT128_BLOCK_SIZE/8];
    uint8_t x[GIFT128_BLOCK_SIZE], y[GIFT128_BLOCK_SIZE], tag[TAG_SIZE];
    masked_rkey m_rkey;

    // save the tag for verification in case out = in
    if (mode == COFB_DECRYPT)
        memcpy(tag, in+in_len, TAG_SIZE);

    gift128_keyschedule(key, m_rkey.rkey, key_m);
    giftb128_encrypt_block(y, m_rkey.rkey, nonce);
    offset[0] = ((uint32_t*)y)[0];
    offset[1] = ((uint32_t*)y)[1];

    while(ad_len > GIFT128_BLOCK_SIZE){
        rho1(x, y, ad, GIFT128_BLOCK_SIZE);
        double_half_block(offset);
        XOR_TOP_BAR_BLOCK((uint32_t *)x, offset);
        giftb128_encrypt_block(y, m_rkey.rkey, x);
        ad += GIFT128_BLOCK_SIZE;
        ad_len -= GIFT128_BLOCK_SIZE;
    }
    
    triple_half_block(offset);
    if((ad_len % GIFT128_BLOCK_SIZE != 0) || (ad_len == 0))
        triple_half_block(offset);
    if (in_len == 0) {
        triple_half_block(offset);
        triple_half_block(offset);
    }

    rho1(x, y, ad, ad_len);
    XOR_TOP_BAR_BLOCK((uint32_t *)x, offset);
    giftb128_encrypt_block(y, m_rkey.rkey, x);

    while (in_len > GIFT128_BLOCK_SIZE){
        double_half_block(offset);
        if (mode == COFB_ENCRYPT)
            rho(y, in, x, out, GIFT128_BLOCK_SIZE);
        else
            rho_prime(y, in, x, out, GIFT128_BLOCK_SIZE);
        XOR_TOP_BAR_BLOCK((uint32_t *)x, offset);
        giftb128_encrypt_block(y, m_rkey.rkey, x);
        in += GIFT128_BLOCK_SIZE;
        out += GIFT128_BLOCK_SIZE;
        in_len -= GIFT128_BLOCK_SIZE;
    }
    
    if (in_len != 0) {
        triple_half_block(offset);
        if(in_len % GIFT128_BLOCK_SIZE != 0)
            triple_half_block(offset);
        if (mode == COFB_ENCRYPT) {
            rho(y, in, x, out, in_len);
            out += in_len;
        }
        else {
            rho_prime(y, in, x, out, in_len);
            in += in_len;
        }
        XOR_TOP_BAR_BLOCK((uint32_t *)x, offset);
        giftb128_encrypt_block(y, m_rkey.rkey, x);
    }
    
    if (mode == COFB_ENCRYPT) { // encryption mode
        memcpy(out, y, TAG_SIZE);
        return 0;
    }
    // decrypting
    ret = 0;
    for(i = 0; i < TAG_SIZE; i++)
        ret |= tag[i] ^ y[i];
    return ret;
}

/**
 * Wrapper for compliance with the API defined in the call for protected
 * implementations from GMU.
 * 
 * Converts an array with 4 mask_*_uint32_t element 2 16-byte byte arrays
 * (NUM_SHARES = 2).
 * The first and second output arrays contain the first and second shares in a
 * byte-wise representation, respectively.
 * 
 * Useful to pass the 16-byte block to mask the internal state and the 16-byte
 * key share as inputs to the Romulus functions.
 */
static void shares_to_bytearr_2(
    uint8_t bytearr_0[],
    uint8_t bytearr_1[],
    const mask_key_uint32_t *ks)
{
    int i;
    // pack the first shares into bytearr_0
    for(i = 0; i < KEY_SIZE/4; i++) {
        bytearr_0[i*4 + 0] = (uint8_t)((ks[i].shares[0] >> 0)  & 0xff);
        bytearr_0[i*4 + 1] = (uint8_t)((ks[i].shares[0] >> 8)  & 0xff);
        bytearr_0[i*4 + 2] = (uint8_t)((ks[i].shares[0] >> 16) & 0xff);
        bytearr_0[i*4 + 3] = (uint8_t)((ks[i].shares[0] >> 24) & 0xff);
    }
    // pack the second shares into bytearr_1
    // use a distinct loop to avoid potential HD-based leakages
    for(i = 0; i < KEY_SIZE/4; i++) {
        bytearr_1[i*4 + 0] = (uint8_t)((ks[i].shares[1] >> 0)  & 0xff);
        bytearr_1[i*4 + 1] = (uint8_t)((ks[i].shares[1] >> 8)  & 0xff);
        bytearr_1[i*4 + 2] = (uint8_t)((ks[i].shares[1] >> 16) & 0xff);
        bytearr_1[i*4 + 3] = (uint8_t)((ks[i].shares[1] >> 24) & 0xff);
    }
}

/**
 * Same as 'shares_to_bytearr_2' but with no masking => only one output buffer.
 */
static void shares_to_bytearr(
    uint8_t bytearr[],
    const mask_m_uint32_t *ms, unsigned long long mlen)
{
    unsigned long long i, r;
    r = mlen % 4;
    for(i = 0; i < mlen/4; i++) {
        bytearr[i*4 + 0] = (uint8_t)((ms[i].shares[0] >> 0)  & 0xff);
        bytearr[i*4 + 1] = (uint8_t)((ms[i].shares[0] >> 8)  & 0xff);
        bytearr[i*4 + 2] = (uint8_t)((ms[i].shares[0] >> 16) & 0xff);
        bytearr[i*4 + 3] = (uint8_t)((ms[i].shares[0] >> 24) & 0xff);
    }
    for(i = 0; i < r; i++)
        bytearr[mlen - r + i] = (uint8_t)((ms[mlen/4].shares[0] >> 8*i)  & 0xff);
}

/**
 * Split the encryption key into two shares and pack the other inputs according
 * to the call for protected software implementations from GMU.
 */
void generate_shares_encrypt(
    const unsigned char *m, mask_m_uint32_t *ms, const unsigned long long mlen,
    const unsigned char *ad, mask_ad_uint32_t *ads , const unsigned long long adlen,
    const unsigned char *npub, mask_npub_uint32_t *npubs,
    const unsigned char *k, mask_key_uint32_t *ks)
{
    unsigned long long i, r;

    // msg is not split into shares, simple copy
    r = mlen % 4;
    for(i = 0; i < mlen/4; i++) {
        ms[i].shares[0]  = (uint32_t)(m[i*4 + 0] << 0);
        ms[i].shares[0] |= (uint32_t)(m[i*4 + 1] << 8);
        ms[i].shares[0] |= (uint32_t)(m[i*4 + 2] << 16);
        ms[i].shares[0] |= (uint32_t)(m[i*4 + 3] << 24);
    }
    // pad with 0s for the last incomplete word
    if (r) {
        ms[mlen/4 + 1].shares[0]  = 0x00000000;
        for(i = 0; i < r; i++)
            ms[mlen/4].shares[0] |= (uint32_t)(m[mlen - r + i] << 8*i);
    }

    // ad is not split into shares, simple copy
    r = adlen % 4;
    for(i = 0; i < adlen/4; i++) {
        ads[i].shares[0]  = (uint32_t)(ad[i*4 + 0] << 0);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 1] << 8);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 2] << 16);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 3] << 24);
    }
    // pad with 0s for the last incomplete word
    if (r) {
        ads[adlen/4 + 1].shares[0]  = 0x00000000;
        for(i = 0; i < r; i++)
            ads[adlen/4].shares[0] |= (uint32_t)(ad[adlen - r + i] << 8*i);
    }

    // npub is not split into shares, simple copy
    for(i = 0; i < GIFT128_BLOCK_SIZE/4; i++) {
        npubs[i].shares[0]  = (uint32_t)(npub[i*4 + 0] << 0);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 1] << 8);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 2] << 16);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 3] << 24);
    }

    // encryption key is split into 2 shares (1st-order masking)
    randombytes((uint8_t *)(&(ks[0].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[1].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[2].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[3].shares[1])), 4);
    ks[0].shares[0] = ks[0].shares[1] ^ ((uint32_t *)k)[0];
    ks[1].shares[0] = ks[1].shares[1] ^ ((uint32_t *)k)[1];
    ks[2].shares[0] = ks[2].shares[1] ^ ((uint32_t *)k)[2];
    ks[3].shares[0] = ks[3].shares[1] ^ ((uint32_t *)k)[3];
}

/**
 * Split the encryption key into two shares and pack the other inputs according
 * to the call for protected software implementations from GMU.
 */
void generate_shares_decrypt(
    const unsigned char *c, mask_m_uint32_t *cs, const unsigned long long clen,
    const unsigned char *ad, mask_ad_uint32_t *ads , const unsigned long long adlen,
    const unsigned char *npub, mask_npub_uint32_t *npubs,
    const unsigned char *k, mask_key_uint32_t *ks)
{
    unsigned long long i, r;

    // msg is not split into shares, simple copy
    r = clen % 4;
    for(i = 0; i < clen/4; i++) {
        cs[i].shares[0]  = (uint32_t)(c[i*4 + 0] << 0);
        cs[i].shares[0] |= (uint32_t)(c[i*4 + 1] << 8);
        cs[i].shares[0] |= (uint32_t)(c[i*4 + 2] << 16);
        cs[i].shares[0] |= (uint32_t)(c[i*4 + 3] << 24);
    }
    // pad with 0s for the last incomplete word
    if (r) {
        cs[clen/4 + 1].shares[0]  = 0x00000000;
        for(i = 0; i < r; i++)
            cs[clen/4].shares[0] |= (uint32_t)(c[clen - r + i] << 8*i);
    }

    // ad is not split into shares, simple copy
    r = adlen % 4;
    for(i = 0; i < adlen/4; i++) {
        ads[i].shares[0]  = (uint32_t)(ad[i*4 + 0] << 0);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 1] << 8);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 2] << 16);
        ads[i].shares[0] |= (uint32_t)(ad[i*4 + 3] << 24);
    }
    // pad with 0s for the last incomplete word
    if (r) {
        ads[adlen/4 + 1].shares[0]  = 0x00000000;
        for(i = 0; i < r; i++)
            ads[adlen/4].shares[0] |= (uint32_t)(ad[adlen - r + i] << 8*i);
    }

    // npub is not split into shares, simple copy
    for(i = 0; i < GIFT128_BLOCK_SIZE/4; i++) {
        npubs[i].shares[0]  = (uint32_t)(npub[i*4 + 0] << 0);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 1] << 8);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 2] << 16);
        npubs[i].shares[0] |= (uint32_t)(npub[i*4 + 3] << 24);
    }

    // encryption key is split into 2 shares (1st-order masking)
    randombytes((uint8_t *)(&(ks[0].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[1].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[2].shares[1])), 4);
    randombytes((uint8_t *)(&(ks[3].shares[1])), 4);
    ks[0].shares[0] = ks[0].shares[1] ^ ((uint32_t *)k)[0];
    ks[1].shares[0] = ks[1].shares[1] ^ ((uint32_t *)k)[1];
    ks[2].shares[0] = ks[2].shares[1] ^ ((uint32_t *)k)[2];
    ks[3].shares[0] = ks[3].shares[1] ^ ((uint32_t *)k)[3];
}

/**
 * Combine the shares into the output ciphertext buffer.
 */
void combine_shares_encrypt(
    const mask_c_uint32_t *cs, unsigned char *c, unsigned long long clen) {
    shares_to_bytearr(c, (mask_m_uint32_t *)cs, clen);
}

/**
 * Combine the shares into the output plaintext buffer.
 */
void combine_shares_decrypt(
    const mask_m_uint32_t *ms, unsigned char *m, unsigned long long mlen) {
    shares_to_bytearr(m, ms, mlen);
}

int crypto_aead_encrypt_shared(
    mask_c_uint32_t* cs, unsigned long long *clen,
    const mask_m_uint32_t *ms, unsigned long long mlen,
    const mask_ad_uint32_t *ads, unsigned long long adlen,
    const mask_npub_uint32_t *npubs,
    const mask_key_uint32_t *ks)
{
    uint8_t key[KEY_SIZE];
    uint8_t key_m[KEY_SIZE];
    shares_to_bytearr_2(key, key_m, ks);

    *clen = mlen + TAG_SIZE;
/*
    return giftcofb_crypt(
        (uint8_t *)(cs[0].shares),
        key, key_m,
        (uint8_t *)(npubs[0].shares),
        (uint8_t *)(ads[0].shares), adlen,
        (uint8_t *)(ms[0].shares), mlen,
        COFB_ENCRYPT);
        */
    return giftcofb_crypt(
        (uint8_t *)(cs),
        key, key_m,
        (uint8_t *)(npubs),
        (uint8_t *)(ads), adlen,
        (uint8_t *)(ms), mlen,
        COFB_ENCRYPT);
}

int crypto_aead_decrypt_shared(
    mask_m_uint32_t* ms, unsigned long long *mlen,
    const mask_c_uint32_t *cs, unsigned long long clen,
    const mask_ad_uint32_t *ads, unsigned long long adlen,
    const mask_npub_uint32_t *npubs,
    const mask_key_uint32_t *ks)
{
    uint8_t key[KEY_SIZE];
    uint8_t key_m[KEY_SIZE];
    shares_to_bytearr_2(key, key_m, ks);

    if (clen < TAG_SIZE)
        return -1;
    *mlen = clen - TAG_SIZE;

    return giftcofb_crypt(
        (uint8_t *)ms,
        key, key_m,
        (uint8_t *)npubs,
        (uint8_t *)ads, adlen,
        (uint8_t *)cs, *mlen,
        COFB_DECRYPT);
}

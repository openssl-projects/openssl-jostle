//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//
//  CCM mode authenticated-encryption context — separate from
//  block_cipher_ctx because CCM doesn't fit the streaming-update model
//  that block_cipher_ctx is built around:
//
//  1. The total plaintext length must be set BEFORE any AAD or
//     plaintext is processed (via EVP_EncryptUpdate(NULL,&,NULL,len)).
//  2. AAD must be passed in a single EVP_EncryptUpdate call.
//  3. Plaintext must be passed in a single EVP_EncryptUpdate call.
//
//  See NIST SP 800-38C and the "CCM Mode" section of OpenSSL's
//  EVP_EncryptInit man page. The SPI layer buffers AAD + plaintext
//  in Java; this C surface is therefore one-shot.

#ifndef CCM_CTX_H
#define CCM_CTX_H

#include <openssl/evp.h>
#include <stdint.h>
#include <stddef.h>
#include "cipher_mode_pad.h"

// CCM nonce length range per NIST SP 800-38C §6.1: 7..13 bytes.
#define CCM_MIN_NONCE_LEN 7
#define CCM_MAX_NONCE_LEN 13

// CCM tag length valid set per NIST SP 800-38C §6.1: {4,6,8,10,12,14,16}.
#define CCM_MIN_TAG_LEN 4
#define CCM_MAX_TAG_LEN 16

// Max CCM key size we admit: 32 bytes for AES-256 / ARIA-256.
#define CCM_MAX_KEY_LEN 32

typedef struct ccm_ctx {
    EVP_CIPHER_CTX *evp;
    uint32_t cipher_id;
    int32_t op_mode;
    size_t key_len;
    uint8_t key[CCM_MAX_KEY_LEN];
    size_t iv_len;
    uint8_t iv[CCM_MAX_NONCE_LEN];
    size_t tag_len;
    uint8_t initialized;
} ccm_ctx;

/**
 * True if tag_len is a valid CCM tag length (NIST SP 800-38C §6.1:
 * {4,6,8,10,12,14,16} bytes). Exposed so the JNI/FFI bridges validate
 * the caller's tag length and return JO_INVALID_TAG_LEN; ccm_ctx_init
 * asserts it as a bridge-validated invariant.
 */
int valid_ccm_tag_len(size_t tag_len);

/**
 * Allocate a new ccm_ctx for the named cipher family.
 * Returns NULL with *err set on failure.
 */
ccm_ctx *ccm_ctx_create(uint32_t cipher_id, int32_t *err);

void ccm_ctx_destroy(ccm_ctx *ctx);

/**
 * Record the key, IV, tag length, and operation mode. Does NOT
 * call into OpenSSL — all EVP work happens in do_encrypt /
 * do_decrypt since CCM needs the plaintext length up-front.
 *
 * Validates:
 *   - key_len matches the cipher_id (16/24/32 for AES/ARIA, 16 for SM4)
 *   - iv_len in [CCM_MIN_NONCE_LEN, CCM_MAX_NONCE_LEN]
 *   - tag_len in {4,6,8,10,12,14,16}
 */
int32_t ccm_ctx_init(ccm_ctx *ctx,
                     int32_t opp_mode,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *iv, size_t iv_len,
                     size_t tag_len);

/**
 * One-shot encrypt: writes ciphertext followed by the tag into out.
 * out_len must be >= pt_len + tag_len.
 *
 * aad may be NULL when aad_len == 0.
 * pt  may be NULL when pt_len == 0.
 *
 * Returns the number of bytes written (pt_len + tag_len) on success,
 * negative JO_* error code on failure.
 */
int32_t ccm_ctx_do_encrypt(ccm_ctx *ctx,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt,  size_t pt_len,
                           uint8_t *out,       size_t out_len);

/**
 * One-shot decrypt: ct is ciphertext+tag (tag is the last tag_len
 * bytes). Writes plaintext into out. out_len must be >= ct_len - tag_len.
 *
 * Returns the number of plaintext bytes written on success,
 * JO_INVALID_CIPHER_TEXT on tag mismatch / authentication failure,
 * negative JO_* on other errors.
 */
int32_t ccm_ctx_do_decrypt(ccm_ctx *ctx,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct,  size_t ct_len,
                           uint8_t *out,       size_t out_len);

/**
 * Required output buffer size for an encrypt of plaintext_len bytes
 * (= plaintext_len + tag_len). Returns 0 for decrypt-side queries —
 * the SPI handles decrypt sizing.
 */
int32_t ccm_ctx_get_output_size(ccm_ctx *ctx, int32_t op_mode, size_t input_len);

#endif // CCM_CTX_H

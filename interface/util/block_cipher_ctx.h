//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

#ifndef BLOCK_CIPHER_SPI_H
#define BLOCK_CIPHER_SPI_H

#include <openssl/evp.h>
#include <openssl/types.h>
#include <stdint.h>
#include "cipher_mode_pad.h"
#include "ctr_u128_t.h"

#define MAX_IV_LEN 16
#define MAX_KEY_LEN 32
#define MAX_TAG_LEN 16

typedef struct block_cipher_ctx {
    EVP_CIPHER_CTX *evp;
    uint32_t cipher_id;
    uint32_t mode_id;
    uint32_t padding;
    int32_t op_mode;
    size_t cipher_block_size;
    size_t processed;
    uint32_t streaming;
    ctr_u128_t *counter; /* tracks counter in ctr mode */
    size_t key_len;
    uint8_t last_key[MAX_KEY_LEN];
    size_t iv_len;
    uint8_t last_iv[MAX_IV_LEN];
    size_t tag_len;
    uint8_t tag_buffer[MAX_TAG_LEN];
    uint32_t tag_index;
} block_cipher_ctx;


/*
 * Creates an empty context
 */
block_cipher_ctx *block_cipher_ctx_create(uint32_t cipher_Id, uint32_t mode_Id, uint8_t padding);

/*
 * Destroy the block_cipher_context releasing any internal state.
 */
void block_cipher_ctx_destroy(block_cipher_ctx *ctx);

/*
 * Init with key and optional IV, mode will determine if and how IV is used
 */
int32_t block_cipher_ctx_init(
    block_cipher_ctx *ctx,
    int32_t opp_mode,
    uint8_t *key,
    size_t key_len,
    uint8_t *iv,
    size_t iv_len,
    int32_t tag_len
);

/*
 * Update AAD.
 */
int32_t block_cipher_ctx_updateAAD(
    block_cipher_ctx *ctx,
    uint8_t *input,
    size_t in_len);

/*
 * Classic block cipher update
 * Returns number of bytes written to output
 */
int32_t block_cipher_ctx_update(
    block_cipher_ctx *ctx,
    uint8_t *input,
    size_t in_len,
    uint8_t *output,
    size_t out_len);


/*
 * Classic block cipher update
 * Returns number of bytes written to output
 */
int32_t block_cipher_ctx_final(
    block_cipher_ctx *ctx,
    uint8_t *output,
    size_t out_len);

/*
 * Set the tag, must be called prior to calling final
 */
int32_t block_cipher_set_tag(block_cipher_ctx *ctx, uint8_t *tag, size_t tag_len);

/*
 * Return the actual size of the block cipher.
 */
int32_t block_cipher_ctx_get_block_size(block_cipher_ctx *ctx);

/*
 * Calculate the minimum byte length for a safe finalisation
 */
int32_t block_cipher_get_final_size(block_cipher_ctx *ctx, size_t len);

/*
 * Return the minimum byte length to absorb the output from an update call.
 */
int32_t block_cipher_get_update_size(block_cipher_ctx *ctx, size_t len);


#endif //BLOCK_CIPHER_SPI_H

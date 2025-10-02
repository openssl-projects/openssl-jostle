//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

#ifndef MLDSA_H
#define MLDSA_H

#include <openssl/types.h>

#include "key_spec.h"

int32_t mldsa_generate_key_pair(key_spec *key_pair, int32_t type, uint8_t *seed, size_t seed_len);

int32_t mldsa_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t mldsa_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t mldsa_get_private_seed(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t mldsa_decode_private_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len);

int32_t mldsa_decode_public_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len);


#define MLDSA_SIGN 0
#define MLDSA_VERIFY  1

#define MLDSA_HASH_NONE 0
// #define MLDSA_HASH_SHA256 1
// #define MLDSA_HASH_SHA512 2
// #define MLDSA_HASH_SHAKE_128 3

#define MLDSA_Mu_INTERNAL 0
#define MLDSA_Mu_EXTERNAL 1
#define MLDSA_Mu_CALCULATE_ONLY 2


#define Mu_BYTES 64
#define TR_PRIVATE_KEY_OFFSET 64
#define TR_LEN 64
#define MAX_CTX_LEN 256
#define MLDSA_SEED_LEN 32

// #define HASH_SHA512_LEN 64

typedef struct mldsa_ctx {
    int32_t type;
    EVP_SIGNATURE *sig;
    EVP_PKEY_CTX *pctx;
    int32_t opp;
    int32_t hash_type;
    EVP_MD_CTX *hash;
    uint8_t tr[TR_LEN];
    uint8_t context[MAX_CTX_LEN];
    int32_t context_len;
    int32_t mu_mode;
    BIO *mu_buf;
} mldsa_ctx;


mldsa_ctx *mldsa_ctx_create(void);

void mldsa_ctx_destroy(mldsa_ctx *ctx);

int32_t mldsa_ctx_init_sign(mldsa_ctx *ctx, const key_spec *key_spec, const uint8_t *sign_ctx, int32_t sign_ctx_len,
                            int32_t mu_mode);

int32_t mldsa_ctx_init_verify(mldsa_ctx *ctx, const key_spec *key_spec, const uint8_t *sign_ctx, int32_t sign_ctx_len,
                              int32_t mu_mode);

int32_t mldsa_ctx_sign(const mldsa_ctx *ctx, const uint8_t *out, const size_t out_len);

int32_t mldsa_ctx_verify(mldsa_ctx *ctx, const uint8_t *sig, const size_t sig_len);

int32_t mldsa_update(const mldsa_ctx *ctx, const uint8_t *in, const size_t in_len);

#endif //MLDSA_H

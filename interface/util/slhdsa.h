//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

#ifndef SLHDSA_H
#define SLHDSA_H
#include <stdint.h>

#include "key_spec.h"




int32_t slh_dsa_generate_key_pair(key_spec *key_pair, int32_t type, uint8_t *seed, size_t seed_len);

int32_t slh_dsa_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t slh_dsa_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t slh_dsa_get_private_seed(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t slh_dsa_decode_private_key(key_spec *key_spec, int32_t typeId,  uint8_t *src, size_t src_len);

int32_t slh_dsa_decode_public_key(key_spec *key_spec, int32_t typeId,  uint8_t *src, size_t src_len);


#define MAX_CTX_LEN 256
#define SLH_DSA_ME_NONE 0
#define SLH_DSA_ME_PURE 1

#define SLH_DSA_SIGN 0
#define SLH_DSA_VERIFY 1

#define SLH_DSA_HASH_NONE 0
#define SLH_DSA_HASH_SHA256 1
#define SLH_DSA_HASH_SHAKE256 2

#define SLH_DSA_NON_DETERMINISTIC 0
#define SLH_DSA_DETERMINISTIC 1

typedef struct slh_dsa_ctx {
    int32_t type;
    EVP_SIGNATURE *sig;
    EVP_PKEY_CTX *pctx;
    int32_t opp;
    int32_t hash_mode;
    uint8_t context[MAX_CTX_LEN];
    int32_t context_len;
    int32_t msg_encoding;
    int32_t deterministic;
    BIO *msg_buf;

} slh_dsa_ctx;



slh_dsa_ctx *slh_dsa_ctx_create(void);

void slh_dsa_ctx_destroy(slh_dsa_ctx *ctx);

int32_t slh_dsa_ctx_init_sign(slh_dsa_ctx *ctx, const key_spec *key_spec, const uint8_t *sign_ctx, int32_t sign_ctx_len,
                              int32_t msg_encoding, int32_t deterministic);

int32_t slh_dsa_ctx_init_verify(slh_dsa_ctx *ctx, const key_spec *key_spec, const uint8_t *sign_ctx, int32_t sign_ctx_len,
                                int32_t msg_encoding, int32_t deterministic);

int32_t slh_dsa_ctx_sign(const slh_dsa_ctx *ctx, const uint8_t *out, const size_t out_len);

int32_t slh_dsa_ctx_verify(const slh_dsa_ctx *ctx, const uint8_t *sig, const size_t sig_len);

int32_t slh_dsa_update(const slh_dsa_ctx *ctx, const uint8_t *in, const size_t in_len);





#endif //SLHDSA_H

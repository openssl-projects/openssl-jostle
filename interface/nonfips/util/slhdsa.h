//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef SLHDSA_H
#define SLHDSA_H
#include <stdint.h>

#include "key_spec.h"




int32_t slh_dsa_generate_key_pair(key_spec *key_pair, int32_t type, uint8_t *seed, size_t seed_len, void *rand_src);

int32_t slh_dsa_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t slh_dsa_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t slh_dsa_decode_private_key(key_spec *key_spec, int32_t typeId,  uint8_t *src, size_t src_len);

int32_t slh_dsa_decode_public_key(key_spec *key_spec, int32_t typeId,  uint8_t *src, size_t src_len);


#define MAX_CTX_LEN 256
#define SLH_DSA_ME_NONE 0
#define SLH_DSA_ME_PURE 1

#define SLH_DSA_SIGN 0
#define SLH_DSA_VERIFY 1

#define SLH_DSA_NON_DETERMINISTIC 0
#define SLH_DSA_DETERMINISTIC 1

/*
 * A non-trivial magic, neither 0 nor 1, so freed or cleared memory does not read as an slh_dsa_ctx.
 * First field, so a handle to another object is refused before anything past its first word is read.
 */
#define SLH_DSA_CTX_KIND 0x53444101u /* "SDA\1" */
#define SLH_DSA_CTX_NONE 0u          /* what a freed ctx is left with; never a valid kind */

typedef struct slh_dsa_ctx {
    uint32_t kind;
    EVP_SIGNATURE *sig;
    EVP_PKEY_CTX *pctx;
    int32_t opp;
    uint8_t context[MAX_CTX_LEN];
    int32_t context_len;
    int32_t msg_encoding;
    int32_t deterministic;
    BIO *msg_buf;

} slh_dsa_ctx;



slh_dsa_ctx *slh_dsa_ctx_create(int32_t *err);

/*
 * JO_SIGNER_CTX_IS_NULL, JO_SLHDSA_CTX_WRONG_KIND or JO_SUCCESS; reads only the kind.
 */
int32_t slh_dsa_ctx_check(const slh_dsa_ctx *ctx);

/* Frees nothing unless ctx is a live slh_dsa_ctx. */
void slh_dsa_ctx_destroy(slh_dsa_ctx *ctx);

int32_t slh_dsa_ctx_init_sign(slh_dsa_ctx *ctx, const key_spec *key_spec, const uint8_t *sign_ctx, int32_t sign_ctx_len,
                              int32_t msg_encoding, int32_t deterministic, void *rand_src);

int32_t slh_dsa_ctx_init_verify(slh_dsa_ctx *ctx, const key_spec *key_spec, const uint8_t *sign_ctx, int32_t sign_ctx_len,
                                int32_t msg_encoding, int32_t deterministic);

/* A written signature consumes the session: the next sign answers JO_NOT_INITIALIZED. */
int32_t slh_dsa_ctx_sign(slh_dsa_ctx *ctx, const uint8_t *out, const size_t out_len, void *rand_src);

/* A verification consumes the session: the next verify answers JO_NOT_INITIALIZED. */
int32_t slh_dsa_ctx_verify(slh_dsa_ctx *ctx, const uint8_t *sig, const size_t sig_len);

int32_t slh_dsa_update(const slh_dsa_ctx *ctx, const uint8_t *in, const size_t in_len);





#endif //SLHDSA_H

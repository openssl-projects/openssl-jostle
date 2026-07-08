//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#ifndef EDEC_H
#define EDEC_H
#include <stdint.h>

#include "key_spec.h"

#define EDEC_SIGN 1
#define EDEC_VERIFY 2

typedef struct edec_ctx {
    EVP_MD_CTX *digest_ctx;
    BIO *message;
    int opp;
} edec_ctx;


int32_t edec_generate_key(key_spec *spec, int32_t type, void *rnd_src);

int32_t edec_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t edec_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t edec_decode_private_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len);

int32_t edec_decode_public_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len);

edec_ctx *edec_ctx_create(int32_t *err);

void edec_ctx_destroy(edec_ctx *edec_ctx);

int32_t edec_ctx_init_sign(edec_ctx *ctx, const key_spec *key_spec, const char *name, int name_len, const uint8_t *context, int32_t context_len, void *rnd_src);

int32_t edec_ctx_init_verify(edec_ctx *ctx, const key_spec *key_spec, const char *name, int name_len, const uint8_t *context, int32_t context_len);

int32_t edec_ctx_update(edec_ctx *ctx, const uint8_t *in, const size_t in_len);

int32_t edec_ctx_sign(edec_ctx *ctx, uint8_t *out, const size_t out_len, void *rnd_src);

int32_t edec_ctx_verify(edec_ctx *ctx, const uint8_t *sig, const size_t sig_len);


#endif //EDEC_H

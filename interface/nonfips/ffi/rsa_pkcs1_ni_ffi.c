//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <stdint.h>
#include <openssl/crypto.h>

#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/rsa_pkcs1.h"
#include "types.h"


// =============================================================
// Lifecycle
// =============================================================

rsa_pkcs1_ctx *JoRSAPKCS1_allocateCipher(int32_t *err) {
    return rsa_pkcs1_ctx_create(err);
}

void JoRSAPKCS1_disposeCipher(rsa_pkcs1_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    rsa_pkcs1_ctx_destroy(ctx);
}


// =============================================================
// Init / doFinal
// =============================================================

int32_t JoRSAPKCS1_init(rsa_pkcs1_ctx *ctx, key_spec *key,
                       int32_t op_mode,
                       void *rnd_src) {
    jo_assert(ctx != NULL);

    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    return rsa_pkcs1_init(ctx, key, op_mode, rnd_src);
}


int32_t JoRSAPKCS1_doFinal(rsa_pkcs1_ctx *ctx,
                          uint8_t *input, size_t input_size,
                          int32_t in_off, int32_t in_len,
                          uint8_t *output, size_t output_size,
                          int32_t out_off,
                          void *rnd_src) {
    jo_assert(ctx != NULL);

    if (input == NULL) {
        return JO_INPUT_IS_NULL;
    }
    if (in_off < 0) {
        return JO_INPUT_OFFSET_IS_NEGATIVE;
    }
    if (in_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (!check_in_range(input_size, (size_t) in_off, (size_t) in_len)) {
        return JO_INPUT_OUT_OF_RANGE;
    }

    if (output == NULL) {
        return rsa_pkcs1_dofinal(ctx,
                                 input + in_off, (size_t) in_len,
                                 NULL, 0,
                                 rnd_src);
    }

    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    if ((size_t) out_off > output_size) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    return rsa_pkcs1_dofinal(ctx,
                             input + in_off, (size_t) in_len,
                             output + (size_t) out_off,
                             output_size - (size_t) out_off,
                             rnd_src);
}

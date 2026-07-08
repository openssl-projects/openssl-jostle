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
#include "../util/rsa_oaep.h"
#include "types.h"


// =============================================================
// Lifecycle
// =============================================================

rsa_oaep_ctx *JoRSAOAEP_allocateCipher(int32_t *err) {
    return rsa_oaep_ctx_create(err);
}

void JoRSAOAEP_disposeCipher(rsa_oaep_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    rsa_oaep_ctx_destroy(ctx);
}


// =============================================================
// Init / doFinal
// =============================================================

int32_t JoRSAOAEP_init(rsa_oaep_ctx *ctx, key_spec *key,
                      int32_t op_mode,
                      const char *oaep_md_name,
                      const char *mgf1_md_name,
                      uint8_t *label, size_t label_len,
                      void *rnd_src) {
    jo_assert(ctx != NULL);

    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (oaep_md_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    return rsa_oaep_init(ctx, key, op_mode,
                         oaep_md_name, mgf1_md_name,
                         label, label_len,
                         rnd_src);
}


int32_t JoRSAOAEP_doFinal(rsa_oaep_ctx *ctx,
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
        // Caller wants required length only.
        return rsa_oaep_dofinal(ctx,
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

    return rsa_oaep_dofinal(ctx,
                            input + in_off, (size_t) in_len,
                            output + (size_t) out_off,
                            output_size - (size_t) out_off,
                            rnd_src);
}

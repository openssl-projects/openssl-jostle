//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>

#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/rsa_oaep.h"
#include "types.h"


/* name_len is the name's UTF-8 byte count: an empty name or an embedded NUL names nothing, as on JNI. */
static int oaep_name_unusable(const char *name, size_t name_len) {
    return name_len == 0 || strnlen(name, name_len) != name_len;
}


// =============================================================
// Lifecycle
// =============================================================

rsa_oaep_ctx *JoRSAOAEP_allocateCipher(int32_t *err) {
    return rsa_oaep_ctx_create(err);
}

void JoRSAOAEP_disposeCipher(rsa_oaep_ctx *ctx) {
    rsa_oaep_ctx_destroy(ctx);
}


// =============================================================
// Init / doFinal
// =============================================================

int32_t JoRSAOAEP_init(rsa_oaep_ctx *ctx, key_spec *key,
                      int32_t op_mode,
                      const char *oaep_md_name, size_t oaep_md_len,
                      const char *mgf1_md_name, size_t mgf1_md_len,
                      uint8_t *label, size_t label_len,
                      void *rnd_src) {
    int32_t ret_code = rsa_oaep_ctx_check(ctx);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }
    ret_code = key_spec_check(key);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }
    if (oaep_md_name == NULL) {
        return JO_NAME_IS_NULL;
    }
    if (oaep_name_unusable(oaep_md_name, oaep_md_len)
        || (mgf1_md_name != NULL && oaep_name_unusable(mgf1_md_name, mgf1_md_len))) {
        return JO_RSA_DIGEST_NOT_SUPPORTED;
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
    int32_t ret_code = rsa_oaep_ctx_check(ctx);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

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

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
#include "../util/ccm_ctx.h"
#include "../util/cipher_mode_pad.h"
#include "types.h"


// =============================================================
// Lifecycle
// =============================================================

ccm_ctx *JoCCM_makeInstance(int32_t cipher_id, int32_t *err) {
    return ccm_ctx_create((uint32_t) cipher_id, err);
}


void JoCCM_dispose(ccm_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    ccm_ctx_destroy(ctx);
}


// =============================================================
// Init
// =============================================================

int32_t JoCCM_init(ccm_ctx *ctx, int32_t op_mode,
                   uint8_t *key, size_t key_len,
                   uint8_t *iv, size_t iv_len,
                   int32_t tag_len) {
    if (ctx == NULL) {
        return JO_FAIL;
    }
    if (key == NULL) {
        return JO_KEY_IS_NULL;
    }
    if (iv == NULL) {
        return JO_IV_IS_NULL;
    }
    if (tag_len < 0) {
        return JO_INVALID_TAG_LEN;
    }
    // CCM tag-length set membership ({4,6,8,10,12,14,16}). Validated in
    // the bridge so util can assert it as an invariant.
    if (!valid_ccm_tag_len((size_t) tag_len)) {
        return JO_INVALID_TAG_LEN;
    }
    // CCM nonce length range [7,13] (NIST SP 800-38C §6.1). Validated in
    // the bridge so util can assert it as an invariant.
    if (iv_len < CCM_MIN_NONCE_LEN || iv_len > CCM_MAX_NONCE_LEN) {
        return JO_INVALID_IV_LEN;
    }
    return ccm_ctx_init(ctx, op_mode, key, key_len, iv, iv_len, (size_t) tag_len);
}


// =============================================================
// doFinal — one shot encrypt/decrypt with optional AAD
// =============================================================

int32_t JoCCM_doFinal(ccm_ctx *ctx,
                     uint8_t *aad, size_t aad_size, int32_t aad_len,
                     uint8_t *input, size_t input_size,
                     int32_t in_off, int32_t in_len,
                     uint8_t *output, size_t output_size,
                     int32_t out_off) {
    if (ctx == NULL) {
        return JO_FAIL;
    }
    // All null / negative scalar checks first, then the range checks —
    // same order as the JNI bridge (ni_doFinal) so both layers return
    // identical codes even for inputs with more than one fault.
    if (aad_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (aad == NULL && aad_len != 0) {
        return JO_INPUT_IS_NULL;
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
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }
    if (out_off < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    if (aad != NULL && !check_in_range(aad_size, 0, (size_t) aad_len)) {
        return JO_INPUT_OUT_OF_RANGE;
    }
    if (!check_in_range(input_size, (size_t) in_off, (size_t) in_len)) {
        return JO_INPUT_OUT_OF_RANGE;
    }
    if ((size_t) out_off > output_size) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    uint8_t *aad_ptr = (aad != NULL) ? aad : NULL;
    uint8_t *in_ptr  = input + (size_t) in_off;
    uint8_t *out_ptr = output + (size_t) out_off;
    size_t out_avail = output_size - (size_t) out_off;

    if (ctx->op_mode == ENCRYPT_MODE) {
        return ccm_ctx_do_encrypt(ctx,
                                  aad_ptr, (size_t) aad_len,
                                  in_ptr,  (size_t) in_len,
                                  out_ptr, out_avail);
    } else if (ctx->op_mode == DECRYPT_MODE) {
        return ccm_ctx_do_decrypt(ctx,
                                  aad_ptr, (size_t) aad_len,
                                  in_ptr,  (size_t) in_len,
                                  out_ptr, out_avail);
    }
    return JO_NOT_INITIALIZED;
}


// =============================================================
// Output sizing
// =============================================================

int32_t JoCCM_getOutputSize(ccm_ctx *ctx, int32_t op_mode, int32_t input_len) {
    if (ctx == NULL) {
        return JO_FAIL;
    }
    if (input_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    return ccm_ctx_get_output_size(ctx, op_mode, (size_t) input_len);
}

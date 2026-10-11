//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "types.h"
#include "../util/mac.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/ops.h"

mac_ctx *JoMAC_allocate(const char *mac_name, size_t mac_name_len, const char *function_name,
                        size_t function_name_len, int32_t *err, int32_t err_len) {
    /* err is jostle's own: a null or empty one is a broken invariant, so it aborts. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);

    if (mac_name == NULL) {
        *err = JO_NAME_IS_NULL;
        return NULL;
    }

    if (function_name == NULL) {
        *err = JO_MAC_FUNCTION_IS_NULL;
        return NULL;
    }

    // Each length is the name's UTF-8 byte count: an empty name or an embedded NUL names nothing, as on JNI.
    if (mac_name_len == 0 || strnlen(mac_name, mac_name_len) != mac_name_len) {
        *err = JO_NAME_NOT_FOUND;
        return NULL;
    }

    if (function_name_len == 0 || strnlen(function_name, function_name_len) != function_name_len) {
        *err = JO_MAC_FUNCTION_NOT_FOUND;
        return NULL;
    }

    return allocate_mac(mac_name, function_name, err);
}

mac_ctx *JoMAC_copy(mac_ctx *ctx, int32_t *err, int32_t err_len) {
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);

    // mac_copy refuses a NULL or foreign handle with a typed code.
    return mac_copy(ctx, err);
}

/*
 * iv carries GMAC's nonce and custom KMAC's customisation string; either may be NULL with a zero length, and the
 * MAC's arm in init_mac_ctx decides whether it needs one. out_len is signed so a negative is refusable; 0 means
 * unspecified.
 */
int32_t JoMAC_init(mac_ctx * ctx, uint8_t *key, size_t key_len, uint8_t *iv, size_t iv_len,
                   uint8_t *custom, size_t custom_len, int32_t out_len) {

    int32_t check_rc = mac_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (key == NULL) {
        return JO_KEY_IS_NULL;
    }

    if (iv == NULL && iv_len != 0) {
        return JO_IV_IS_NULL;
    }

    if (custom == NULL && custom_len != 0) {
        return JO_INPUT_IS_NULL;
    }

    if (out_len < 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }

    return mac_init(ctx, key, key_len, iv, iv_len, custom, custom_len, (size_t) out_len);
}

int32_t JoMAC_updateByte(mac_ctx *ctx, uint8_t b) {

    int32_t check_rc = mac_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    return mac_update(ctx, &b, 0, 1);
}

int32_t JoMAC_update(mac_ctx *ctx, uint8_t *input, size_t input_size, int32_t input_offset, int32_t input_len) {

    int32_t check_rc = mac_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    if (input == NULL) {
        return JO_INPUT_IS_NULL;
    }

    if (input_offset < 0) {
        return JO_INPUT_OFFSET_IS_NEGATIVE;
    }

    if (input_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }

    if (!check_in_range(input_size, (size_t) input_offset, (size_t) input_len)) {
        return JO_INPUT_OUT_OF_RANGE;
    }
    return mac_update(ctx, input, input_offset, input_len);
}

int32_t JoMAC_final(mac_ctx *ctx, uint8_t *output, size_t output_size, int32_t output_offset) {

    int32_t check_rc = mac_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (output_offset < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }

    if (OPS_INT32_OVERFLOW_3 output_size > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    int32_t m_len = mac_len(ctx);
    if (UNSUCCESSFUL(m_len)) {
        return m_len;
    }

    if (!check_in_range(output_size, output_offset, m_len)) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }


    return mac_final(ctx, output, output_offset, (int32_t) output_size);
}

int32_t JoMAC_len(mac_ctx *ctx) {
    int32_t check_rc = mac_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    return mac_len(ctx);
}

int32_t JoMAC_lenMeta(mac_ctx *ctx) {
    int32_t check_rc = mac_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    // Keyless: answers before init.
    return mac_len_for(ctx);
}

int32_t JoMAC_reset(mac_ctx *ctx) {
    // mac_reset refuses a NULL or foreign handle, and an uninitialised one.
    return mac_reset(ctx);
}

void JoMAC_free(mac_ctx *ctx) {
    // mac_free frees nothing on a NULL or wrong kind.
    mac_free(ctx);
}

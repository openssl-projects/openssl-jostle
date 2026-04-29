//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stddef.h>
#include <stdint.h>

#include "types.h"
#include "../util/mac.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"

mac_ctx *MAC_allocate(const char *mac_name, const char *function_name, int32_t *err) {
    mac_ctx *out_ctx = NULL;

    jo_assert(err != NULL);

    if (mac_name == NULL) {
        *err = JO_NAME_IS_NULL;
        return NULL;
    }

    if (function_name == NULL) {
        *err = JO_MAC_FUNCTION_IS_NULL;
        return NULL;
    }

    out_ctx = allocate_mac(mac_name, function_name, err);
    return out_ctx;
}

int32_t MAC_init(mac_ctx * ctx, uint8_t *key, size_t key_len) {

    jo_assert(ctx != NULL);

    if (key == NULL) {
        return JO_KEY_IS_NULL;
    }
    return mac_init(ctx, key, key_len);
}

int32_t MAC_update(mac_ctx *ctx, uint8_t *input, size_t input_size, int32_t input_offset, int32_t input_len) {

    jo_assert(ctx != NULL);

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

int32_t MAC_final(mac_ctx *ctx, uint8_t *output, size_t output_size, int32_t output_offset) {

    jo_assert(ctx != NULL);

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (output_offset < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
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

int32_t MAC_len(mac_ctx *ctx) {
    jo_assert(ctx != NULL);
    return mac_len(ctx);
}

int32_t MAC_reset(mac_ctx *ctx) {
    if (ctx == NULL) {
        // Observed spurious resets from within the JVMs provider logic in the past.
        return JO_SUCCESS;
    }
    return mac_reset(ctx);
}

void MAC_free(mac_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    mac_free(ctx);
}



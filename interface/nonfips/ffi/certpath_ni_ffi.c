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
#include "../util/certpath.h"
#include "../util/jo_assert.h"
#include "types.h"

/*
 * FFI bridge for certification path validation. Symbol Jo-prefixed so it
 * cannot clash with a libcrypto export. Returns identical error codes to the
 * JNI bridge (certpath_ni_jni.c) for identical inputs — the two are checked
 * against each other by the same limit tests on both legs.
 *
 * Unlike JNI the caller's array sizes are not discoverable here, so they are
 * PARAMETERS and are range-checked against the data actually supplied.
 */
#define MAX_CERTS 256

int32_t JoCertPath_verify(const uint8_t *der, int32_t der_len,
                          const int32_t *sizes, int32_t sizes_len,
                          int32_t count, int32_t anchor_count,
                          int64_t time_secs, int32_t strict,
                          uint8_t *chain_out, int32_t chain_out_len,
                          int32_t *out_info, int32_t out_info_len)
{
    certpath_result result;
    int32_t ret;
    int32_t i;
    size_t total = 0;

    memset(&result, 0, sizeof(result));

    if (der == NULL) {
        return JO_INPUT_IS_NULL;
    }
    if (sizes == NULL || out_info == NULL || chain_out == NULL) {
        return JO_OUTPUT_IS_NULL;
    }
    if (der_len <= 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (count > MAX_CERTS) {
        return JO_INPUT_TOO_LONG_INT32;
    }
    if (count < 2 || anchor_count < 1 || anchor_count >= count) {
        return JO_INPUT_OUT_OF_RANGE;
    }
    if (sizes_len < count) {
        return JO_INPUT_OUT_OF_RANGE;
    }
    if (out_info_len < count + 3) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }
    if (chain_out_len < 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }
    for (i = 0; i < count; i++) {
        if (sizes[i] <= 0) {
            return JO_INPUT_LEN_IS_NEGATIVE;
        }
        total += (size_t) sizes[i];
        if (total > (size_t) der_len) {
            return JO_INPUT_OUT_OF_RANGE;
        }
    }

    ret = certpath_verify(der, (size_t) der_len, sizes, count, anchor_count,
                          time_secs, strict, &result);
    if (ret != JO_SUCCESS) {
        if (ret == JO_CERT_DECODE_FAILED) {
            out_info[0] = ret;
            out_info[1] = result.depth;   /* which certificate */
            out_info[2] = 0;
        }
        certpath_result_free(&result);
        return ret;
    }

    if (result.chain_len > (size_t) chain_out_len) {
        certpath_result_free(&result);
        return JO_OUTPUT_TOO_SMALL;
    }
    if (result.chain_len > 0) {
        memcpy(chain_out, result.chain_der, result.chain_len);
    }
    out_info[0] = result.error;
    out_info[1] = result.depth;
    out_info[2] = result.chain_count;
    for (i = 0; i < result.chain_count; i++) {
        out_info[3 + i] = result.chain_sizes[i];
    }
    certpath_result_free(&result);
    return JO_SUCCESS;
}

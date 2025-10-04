//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <assert.h>
#include <stdlib.h>
#include "../util/asn1_util.h"
#include "../util/bc_err_codes.h"
#include "types.h"
#include "../util/ops.h"

asn1_ctx *ASN1_allocate(void) {
    asn1_ctx *ctx = asn1_writer_allocate();
    assert(ctx != NULL);
    return ctx;
}


void ASN1_dispose(asn1_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    asn1_writer_free(ctx);
}

int32_t ASN1_encodePublicKey(asn1_ctx *asn1_ctx, key_spec *key_spec) {
    assert(asn1_ctx != NULL);
    if (key_spec == NULL) {
        return JO_KEY_IS_NULL;
    }

    if (key_spec->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    size_t buf_len = 0;
    if (1 != asn1_writer_encode_public_key(asn1_ctx, key_spec, &buf_len)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_1 buf_len > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) buf_len;
}

int32_t ASN1_encodePrivateKey(asn1_ctx *asn1_ctx, key_spec *key_spec) {
    assert(asn1_ctx != NULL);

    if (key_spec == NULL) {
        return JO_KEY_IS_NULL;
    }

    if (key_spec->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    size_t buf_len = 0;
    if (!asn1_writer_encode_private_key(asn1_ctx, key_spec, &buf_len)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_1 buf_len > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) buf_len;
}

int32_t ASN1_getData(asn1_ctx *asn1_ctx, uint8_t *output, size_t output_len) {
    assert(asn1_ctx != NULL);
    size_t buf_len = 0;

    const int32_t ret = asn1_writer_get_content(asn1_ctx, output, &buf_len, output_len);

    if (ret != 1) {
        return ret;
    }


    if (OPS_INT32_OVERFLOW_1 buf_len > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) buf_len;
}

key_spec *ASN1_fromPrivateKeyInfo(
    uint8_t *input,
    size_t input_len_size,
    int32_t in_off,
    int32_t in_len,
    int32_t *ret_code) {
    *ret_code = JO_FAIL;

    key_spec *key_spec = NULL;

    if (input == NULL) {
        *ret_code = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (in_off < 0) {
        *ret_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        *ret_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(input_len_size, in_off, in_len)) {
        *ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    // out_off is asserted non-negative by this point
    const uint8_t *data = input + in_off;

    key_spec = asn1_writer_decode_private_key(data, in_len, ret_code);

exit:
    return key_spec;
}

key_spec *ASN1_fromPublicKeyInfo(
    uint8_t *input, size_t input_len_size, int32_t in_off, int32_t in_len, int32_t *ret_code) {
    *ret_code = JO_FAIL;

    key_spec *key_spec = NULL;

    if (in_off < 0) {
        *ret_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        *ret_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(input_len_size, in_off, in_len)) {
        *ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    // out_off is asserted non-negative by this point
    const uint8_t *data = input + in_off;

    key_spec = asn1_writer_decode_public_key(data, in_len, ret_code);

exit:
    return key_spec;
}

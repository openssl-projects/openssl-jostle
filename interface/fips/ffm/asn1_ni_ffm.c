//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <stdlib.h>
#include <string.h>

#include "../util/asn1_util.h"
#include "../util/bc_err_codes.h"
#include "types.h"
#include "../util/ops.h"
#include "../util/jo_assert.h"

asn1_ctx *JoASN1_allocate(int32_t *err) {
    asn1_ctx *ctx = asn1_writer_allocate(err);
    jo_assert(ctx != NULL);
    return ctx;
}


void JoASN1_dispose(asn1_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    asn1_writer_free(ctx);
}

int32_t JoASN1_encodePublicKey(asn1_ctx *asn1_ctx, key_spec *key_spec) {
    if (asn1_ctx == NULL) {
        return JO_ASN1_CTX_IS_NULL;
    }
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

    if (OPS_INT32_OVERFLOW_1 buf_len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) buf_len;
}

int32_t JoASN1_encodePrivateKey(asn1_ctx *asn1_ctx, key_spec *key_spec, const char *option_string,
                                size_t option_string_len) {
    if (asn1_ctx == NULL) {
        return JO_ASN1_CTX_IS_NULL;
    }


    if (key_spec == NULL) {
        return JO_KEY_IS_NULL;
    }

    if (key_spec->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    int encoding_option = PRIVATE_KEY_DEFAULT_ENCODING;

    // option_string arrives NUL-terminated from the Java arena
    // (Arena.allocateFrom(String)), whose byteSize() — passed as
    // option_string_len — is strlen + 1 (the terminator). Compare exactly
    // like the JNI twin with strcmp — NOT a prefix match against the length.
    // An interior NUL would make strlen stop short of option_string_len - 1;
    // the JNI twin's GetStringUTFChars encodes such a NUL as 0xC0 0x80 so it
    // never matches "default"/"seed_only" there. Reject it here too so both
    // bridges return identical codes for identical inputs.
    if (option_string != NULL) {
        if (option_string_len == 0 || strlen(option_string) != option_string_len - 1) {
            return JO_INVALID_KEY_ENCODING_OPTION;
        }
        if (strcmp(PRIVATE_KEY_DEFAULT_ENCODING_OPTION, option_string) == 0) {
            encoding_option = PRIVATE_KEY_DEFAULT_ENCODING;
        } else if (strcmp(PRIVATE_KEY_SEED_ONLY_ENCODING_OPTION, option_string) == 0) {
            encoding_option = PRIVATE_KEY_SEED_ONLY_ENCODING;
        } else {
            return JO_INVALID_KEY_ENCODING_OPTION;
        }
    }


    size_t buf_len = 0;
    {
        int32_t r = asn1_writer_encode_private_key(asn1_ctx, key_spec, &buf_len, encoding_option);
        if (r != 1) {
            // r is either 0 (generic OpenSSL error) or a specific negative
            // error code propagated from the util.
            return (r == 0) ? JO_OPENSSL_ERROR : r;
        }
    }

    if (OPS_INT32_OVERFLOW_1 buf_len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) buf_len;
}

int32_t JoASN1_getData(asn1_ctx *asn1_ctx, uint8_t *output, size_t output_len) {
    if (asn1_ctx == NULL) {
        return JO_ASN1_CTX_IS_NULL;
    }
    size_t buf_len = 0;

    const int32_t ret = asn1_writer_get_content(asn1_ctx, output, &buf_len, output_len);

    if (ret != 1) {
        return ret;
    }


    if (OPS_INT32_OVERFLOW_1 buf_len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) buf_len;
}

key_spec *JoASN1_fromPrivateKeyInfo(
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

    // in_off is non-negative by this point (checked above)
    const uint8_t *data = input + in_off;

    key_spec = asn1_writer_decode_private_key(data, in_len, ret_code);

exit:
    return key_spec;
}

key_spec *JoASN1_fromPublicKeyInfo(
    uint8_t *input, size_t input_len_size, int32_t in_off, int32_t in_len, int32_t *ret_code) {
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

    // in_off is non-negative by this point (checked above)
    const uint8_t *data = input + in_off;

    key_spec = asn1_writer_decode_public_key(data, in_len, ret_code);

exit:
    return key_spec;
}

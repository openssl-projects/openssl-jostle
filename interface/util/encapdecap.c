//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "encapdecap.h"


#include <openssl/err.h>
#include <openssl/evp.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

int32_t encap(const key_spec *key_spec, const char *kem, uint8_t *secret, size_t secret_len, uint8_t *out,
              const size_t out_len, void *rand_src) {
    jo_assert(key_spec != NULL);
    jo_assert(key_spec->key != NULL);
    jo_assert(secret != NULL);

    int32_t ret = 0;
    EVP_PKEY_CTX *ctx = NULL;


    if (rand_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    rand_set_java_srand_call(rand_src);

    ERR_clear_error();

    ctx = EVP_PKEY_CTX_new_from_pkey(get_global_jostle_ossl_lib_ctx(), key_spec->key, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1101);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 EVP_PKEY_encapsulate_init(ctx,NULL) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1102);
        goto exit;
    }

    if (kem != NULL) {
        if (OPS_OPENSSL_ERROR_3 EVP_PKEY_CTX_set_kem_op(ctx, kem) <= 0) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(1103);
            goto exit;
        }
    }

    size_t min_len = 0;
    // Capture the caller's secret buffer size before the size-query call
    // mutates secret_len to the required size.
    const size_t user_secret_size = secret_len;

    if (OPS_OPENSSL_ERROR_4 EVP_PKEY_encapsulate(ctx, NULL, &min_len, secret, &secret_len) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(1104);
        goto exit;
    }


    if (OPS_INT32_OVERFLOW_1 min_len > INT_MAX) {
        ret = JO_OUTPUT_SIZE_INT_OVERFLOW;
        goto exit;
    }

    if (out == NULL) {
        ret = (int32_t) min_len;
        goto exit;
    }

    if (out_len < min_len) {
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    if (user_secret_size < secret_len) {
        // Mirrors the ciphertext-buffer-too-small check above so callers get
        // a clean diagnostic instead of an opaque -2105 OPS-encoded failure
        // from the second EVP_PKEY_encapsulate call.
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_5 EVP_PKEY_encapsulate(ctx, out, &min_len, secret, &secret_len) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(1105);
        goto exit;
    }

    ret = (int32_t) min_len;


exit:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return ret;
}

int32_t decap(const key_spec *key_spec, const char *kem, const uint8_t *input, const size_t in_len, uint8_t *out,
              const size_t out_len) {
    jo_assert(key_spec != NULL);
    jo_assert(key_spec->key != NULL);
    jo_assert(input != NULL);

    int32_t ret = 0;
    EVP_PKEY_CTX *ctx = NULL;

    ERR_clear_error();

    ctx = EVP_PKEY_CTX_new_from_pkey(get_global_jostle_ossl_lib_ctx(), key_spec->key, NULL);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1201);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 EVP_PKEY_decapsulate_init(ctx,NULL) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1202);
        goto exit;
    }

    if (kem != NULL) {
        if (OPS_OPENSSL_ERROR_3 EVP_PKEY_CTX_set_kem_op(ctx, kem) <= 0) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(1203);
            goto exit;
        }
    }

    size_t min_len = 0;
    if (OPS_OPENSSL_ERROR_4 EVP_PKEY_decapsulate(ctx, NULL, &min_len, input, in_len) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(1204);
        goto exit;
    }


    if (OPS_INT32_OVERFLOW_1 min_len > INT_MAX) {
        ret = JO_OUTPUT_SIZE_INT_OVERFLOW;
        goto exit;
    }

    if (out == NULL) {
        ret = (int32_t) min_len;
        goto exit;
    }

    if (out_len < min_len) {
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_5 EVP_PKEY_decapsulate(ctx, out, &min_len, input, in_len) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_5(1205);
        goto exit;
    }

    ret = (int32_t) min_len;


exit:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return ret;
}

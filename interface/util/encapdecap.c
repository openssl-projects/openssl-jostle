//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "encapdecap.h"

#include <assert.h>
#include <openssl/evp.h>

#include "bc_err_codes.h"
#include "ops.h"

int32_t encap(const key_spec *key_spec, const char *kem, uint8_t *secret, size_t secret_len, uint8_t *out,
              const size_t out_len) {
    int32_t ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key_spec->key, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET(101);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 EVP_PKEY_encapsulate_init(ctx,NULL) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET(102);
        goto exit;
    }

    if (kem != NULL) {
        if (OPS_OPENSSL_ERROR_3 EVP_PKEY_CTX_set_kem_op(ctx, kem) <= 0) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET(103);
            goto exit;
        }
    }

    size_t min_len = 0;
    if (OPS_OPENSSL_ERROR_4 EVP_PKEY_encapsulate(ctx, NULL, &min_len, secret, &secret_len) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET(104);
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

    if (OPS_OPENSSL_ERROR_5 EVP_PKEY_encapsulate(ctx, out, &min_len, secret, &secret_len) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET(105);
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
    int32_t ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key_spec->key, NULL);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET(101);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 EVP_PKEY_decapsulate_init(ctx,NULL) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET(102);
        goto exit;
    }

    if (kem != NULL) {
        if (OPS_OPENSSL_ERROR_3 EVP_PKEY_CTX_set_kem_op(ctx, kem) <= 0) {
            ret = JO_OPENSSL_ERROR OPS_OFFSET(103);
            goto exit;
        }
    }

    size_t min_len = 0;
    if (OPS_OPENSSL_ERROR_4 EVP_PKEY_decapsulate(ctx, NULL, &min_len, input, in_len) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET(104);
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
        ret = JO_OPENSSL_ERROR OPS_OFFSET(105);
        goto exit;
    }

    ret = (int32_t) min_len;


exit:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return ret;
}

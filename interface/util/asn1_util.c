//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "asn1_util.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include "bc_err_codes.h"
#include "key_spec.h"
#include "ops.h"

asn1_ctx *asn1_writer_allocate(void) {
    asn1_ctx *ctx = OPENSSL_zalloc(sizeof(asn1_ctx));
    assert(ctx != NULL);
    ctx->buffer = BIO_new(BIO_s_mem());
    assert(ctx->buffer != NULL);
    return ctx;
}

void asn1_writer_free(asn1_ctx *ctx) {
    if (ctx->buffer != NULL) {
        BIO_free_all(ctx->buffer);
    }

    OPENSSL_clear_free(ctx, sizeof (*ctx));
}

/**
 * Copy buffered output/
 * @param ctx  the ctx
 * @param output the data, set null to return length only
 * @param written set to the amount written
 * @param output_len the length of the output.
 * @return 1 = success, 0 = failure
 */
int32_t asn1_writer_get_content(asn1_ctx *ctx, uint8_t *output, size_t *written, const size_t output_len) {
    assert(ctx != NULL);
    assert(ctx->buffer != NULL);
    uint8_t *buffer = NULL;

    *written = BIO_get_mem_data(ctx->buffer, &buffer);

    if (output != NULL) {
        if (output_len != *written) {
            return JO_OUTPUT_OUT_OF_RANGE;
        }

        memcpy(output, buffer, *written);
    }

    return 1;
}


int32_t asn1_writer_encode_public_key(asn1_ctx *ctx, key_spec *key_spec, size_t *buf_len) {
    assert(ctx != NULL);
    assert(key_spec != NULL);
    assert(key_spec->key != NULL);


    if (1 != i2d_PUBKEY_bio(ctx->buffer, key_spec->key)) {
        return JO_OPENSSL_ERROR;
    }

    *buf_len = BIO_get_mem_data(ctx->buffer, NULL);

    return 1;
}


/**
 * Create a seed only encoding.
 * @param ctx
 * @param key_spec
 * @return 0 if there is a problem
 */
static int32_t seed_only_encoder(asn1_ctx *ctx, key_spec *key_spec) {
    // TODO Seed only encoding logic
    // Add logic to detect OpenSSL version and use that for seed only encoding.
    // Otherwise, default to using the templates.
    //

    if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-44")) {
        uint8_t b[sizeof(mldsa44)];
        memcpy(b, mldsa44, sizeof(mldsa44));

        if (
            OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
            return 0;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mldsa44)) < 0) {
            return 0;
        }
        OPENSSL_cleanse(b, sizeof(mldsa44));
        return 1;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-65")) {
        uint8_t b[sizeof(mldsa65)];
        memcpy(b, mldsa65, sizeof(mldsa65));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
            return 0;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mldsa65)) < 0) {
            return 0;
        }
        OPENSSL_cleanse(b, sizeof(mldsa65));
        return 1;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-87")) {
        uint8_t b[sizeof(mldsa87)];
        memcpy(b, mldsa87, sizeof(mldsa87));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
            return 0;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mldsa87)) < 0) {
            return 0;
        }
        OPENSSL_cleanse(b, sizeof(mldsa87));
        return 1;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-512")) {
        uint8_t b[sizeof(mlkem512)];
        memcpy(b, mlkem512, sizeof(mlkem512));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 64, NULL)) {
            return 0;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mlkem512)) < 0) {
            return 0;
        }
        OPENSSL_cleanse(b, sizeof(mlkem512));
        return 1;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-768")) {
        uint8_t b[sizeof(mlkem768)];
        memcpy(b, mlkem768, sizeof(mlkem768));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 64, NULL)) {
            return 0;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mlkem768)) < 0) {
            return 0;
        }
        OPENSSL_cleanse(b, sizeof(mlkem768));
        return 1;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-1024")) {
        uint8_t b[sizeof(mlkem1024)];
        memcpy(b, mlkem1024, sizeof(mlkem1024));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 64, NULL)) {
            return 0;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mlkem1024)) < 0) {
            return 0;
        }
        OPENSSL_cleanse(b, sizeof(mlkem1024));
        return 1;
    }

    return 0;
}


int32_t asn1_writer_encode_private_key(asn1_ctx *ctx, key_spec *key_spec, size_t *buf_len, int encoding_option) {
    assert(ctx != NULL);
    assert(key_spec != NULL);
    assert(key_spec->key != NULL);


    switch (encoding_option) {
        case PRIVATE_KEY_DEFAULT_ENCODING:
            if (!i2d_PrivateKey_bio(ctx->buffer, key_spec->key)) {
                return 0;
            }
            break;
        case PRIVATE_KEY_SEED_ONLY_ENCODING:
            if (!seed_only_encoder(ctx, key_spec)) {
                return 0;
            }
            break;
        default:
            return 0;
    }


    *buf_len = BIO_get_mem_data(ctx->buffer, NULL);

    return 1;
}


key_spec *asn1_writer_decode_private_key(const uint8_t *src, size_t src_len, int32_t *ret_code) {
    *ret_code = JO_FAIL;
    EVP_PKEY *new_key = NULL;

    if (src == NULL) {
        *ret_code = JO_INPUT_IS_NULL;
        goto err;
    }

    if (OPS_INT32_OVERFLOW_1 src_len > INT_MAX) {
        *ret_code = JO_INPUT_TOO_LONG_INT32;
        return NULL;
    }

    const long _src_len = (int32_t) src_len;
    const uint8_t *_src = src;


    new_key = EVP_PKEY_new();


    const EVP_PKEY *new_key_ = d2i_PrivateKey(EVP_PKEY_NONE, &new_key, &_src, _src_len);

    if (new_key_ == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto err;
    }

    if (OPS_POINTER_CHANGE new_key != new_key_) {
        *ret_code = JO_UNEXPECTED_POINTER_CHANGE;
        goto err;
    }


    key_spec *key = OPENSSL_zalloc(sizeof(key_spec));
    assert(key != NULL);

    key->key = new_key;

    *ret_code = JO_SUCCESS;
    return key;

err:
    EVP_PKEY_free(new_key);
    return NULL;
}


key_spec *asn1_writer_decode_public_key(const uint8_t *src, size_t src_len, int32_t *ret_code) {
    *ret_code = JO_FAIL;
    EVP_PKEY *new_key = NULL;

    if (src == NULL) {
        *ret_code = JO_INPUT_IS_NULL;
        return NULL;
    }

    if (OPS_INT32_OVERFLOW_1 src_len > INT_MAX) {
        *ret_code = JO_INPUT_TOO_LONG_INT32;
        return NULL;
    }

    const long _src_len = (int32_t) src_len;

    new_key = EVP_PKEY_new();

    const uint8_t *_src = src;

    const EVP_PKEY *new_key_ = d2i_PUBKEY(&new_key, &_src, _src_len);

    if (new_key_ == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto err;
    }

    if (OPS_POINTER_CHANGE new_key != new_key_) {
        *ret_code = JO_UNEXPECTED_POINTER_CHANGE;
        goto err;
    }

    key_spec *key = OPENSSL_zalloc(sizeof(key_spec));
    assert(key != NULL);

    // key->type = spec_type;
    key->key = new_key;

    *ret_code = JO_SUCCESS;
    return key;

err:
    EVP_PKEY_free(new_key);
    return NULL;
}

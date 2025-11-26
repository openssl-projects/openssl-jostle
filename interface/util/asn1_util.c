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

static uint8_t mldsa44[] = {
    48, 52, 2, 1, 0, 48, 11, 6, 9, 96, -122, 72, 1, 101,
    3, 4, 3, 17, 4, 34, -128, 32, 0, 0, 0, 24, -114,
    -53, -113, 95, -119, -16, 39, 21, 113, 55, -26, 114,
    -74, -30, -20, -39, 107, 62, 87, 20, 41, 34, 90, -18,
    -39, -100, -91, -10
}; // Seed at byte 22 for 32

static uint8_t mldsa65[] = {
    48, 52, 2, 1, 0, 48, 11, 6, 9, 96, -122, 72, 1, 101,
    3, 4, 3, 18, 4, 34, -128, 32, 8, -114, 106, -34, 33,
    -98, 52, 82, -49, 38, 83, 64, 94, -40, -4, 34, -102,
    114, -44, 79, 63, -108, 20, 90, 127, 120, -99, -103,
    -60, -128, -41, 87
};

static uint8_t mldsa87[] = {
    48, 52, 2, 1, 0, 48, 11, 6, 9, 96, -122, 72, 1, 101,
    3, 4, 3, 19, 4, 34, -128, 32, -53, 1, -80, -43, -69,
    -53, -31, -23, 13, 107, 112, 73, -105, -65, 120, 123,
    87, 81, 58, 107, 18, 65, -62, -8, 92, 36, 126, -97,
    -4, 64, 93, -86
};


static uint8_t mlkem512[] = {
    48, 84, 2, 1, 0, 48, 11, 6, 9, 96, -122, 72, 1, 101, 3,
    4, 4, 1, 4, 66, -128, 64, -21, -50, 86, -11, -120, -111,
    60, 38, 98, 62, 7, 9, 64, 49, -67, -88, -37, 65, 3, -70,
    -119, -109, -22, 120, -69, 95, 89, 72, -79, -53, -100,
    -112, -103, 49, -118, 107, -10, 52, -4, 35, -69, 17, 67,
    58, -24, -123, -77, -70, 74, 125, -83, -33, -126, 34, 32,
    24, 28, -99, -53, 31, 23, 97, -59, -111
};

static uint8_t mlkem768[] = {
    48, 84, 2, 1, 0, 48, 11, 6, 9, 96, -122, 72, 1, 101, 3,
    4, 4, 2, 4, 66, -128, 64, -70, -57, -85, 79, -37, -43,
    102, 66, 26, -118, -59, 37, 104, 86, -89, -108, 45, -25,
    13, 61, -80, 10, -55, 30, 47, -57, 117, -72, -44, -66,
    61, 88, -128, 21, -88, 9, -1, 26, -103, 33, -26, 72, -32,
    -33, -72, 26, -101, 64, 28, -21, 94, 113, 22, -70, -20,
    -78, 23, 40, 16, 12, 60, 6, -109, -89
}; // Seed at byte 22 for 64


static uint8_t mlkem1024[] = {
    48, 84, 2, 1, 0, 48, 11, 6, 9, 96, -122, 72, 1, 101, 3, 4,
    4, 3, 4, 66, -128, 64, -26, -73, 52, -19, 111, 116, 81, 6,
    72, -100, 120, -75, -90, -118, 44, -100, 59, 41, -35, 81,
    -109, -121, -42, -37, -102, 11, -9, 3, -50, -59, 30, -15,
    9, 46, -71, 106, -45, 2, -126, 64, 108, 114, -67, -91, -68,
    38, -77, 97, -56, 126, -8, -43, 127, -30, 2, -60, 95, -74,
    125, -101, 88, 35, -17, 89
};


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

            // NB hack until official support in OpenSSL
            // This is not intended to be robust implementation and will be replaced

            if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-44")) {
                uint8_t b[sizeof(mldsa44)];
                memcpy(b, mldsa44, sizeof(mldsa44));

                if (
                    1 != EVP_PKEY_get_octet_string_param(
                        key_spec->key,
                        OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
                    return 0;
                }

                if (BIO_write(ctx->buffer, b, sizeof(mldsa44)) < 0) {
                    return 0;
                }
                OPENSSL_cleanse(b, sizeof(mldsa44));
            } else if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-65")) {
                uint8_t b[sizeof(mldsa65)];
                memcpy(b, mldsa65, sizeof(mldsa65));

                if (
                    1 != EVP_PKEY_get_octet_string_param(
                        key_spec->key,
                        OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
                    return 0;
                }

                if (BIO_write(ctx->buffer, b, sizeof(mldsa65)) < 0) {
                    return 0;
                }
                OPENSSL_cleanse(b, sizeof(mldsa65));
            } else if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-87")) {
                uint8_t b[sizeof(mldsa87)];
                memcpy(b, mldsa87, sizeof(mldsa87));

                if (
                    1 != EVP_PKEY_get_octet_string_param(
                        key_spec->key,
                        OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
                    return 0;
                }

                if (BIO_write(ctx->buffer, b, sizeof(mldsa87)) < 0) {
                    return 0;
                }
                OPENSSL_cleanse(b, sizeof(mldsa87));
            } else if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-512")) {
                uint8_t b[sizeof(mlkem512)];
                memcpy(b, mlkem512, sizeof(mlkem512));

                if (
                    1 != EVP_PKEY_get_octet_string_param(
                        key_spec->key,
                        OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 64, NULL)) {
                    return JO_OPENSSL_ERROR;
                }

                if (BIO_write(ctx->buffer, b, sizeof(mlkem512)) < 0) {
                    return 0;
                }
                OPENSSL_cleanse(b, sizeof(mlkem512));
            } else if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-768")) {
                uint8_t b[sizeof(mlkem768)];
                memcpy(b, mlkem768, sizeof(mlkem768));

                if (
                    1 != EVP_PKEY_get_octet_string_param(
                        key_spec->key,
                        OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 64, NULL)) {
                    return 0;
                }

                if (BIO_write(ctx->buffer, b, sizeof(mlkem768)) < 0) {
                    return 0;
                }
                OPENSSL_cleanse(b, sizeof(mlkem768));
            } else if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-1024")) {
                uint8_t b[sizeof(mlkem1024)];
                memcpy(b, mlkem1024, sizeof(mlkem1024));

                if (
                    1 != EVP_PKEY_get_octet_string_param(
                        key_spec->key,
                        OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 64, NULL)) {
                    return 0;
                }

                if (BIO_write(ctx->buffer, b, sizeof(mlkem1024)) < 0) {
                    return 0;
                }
                OPENSSL_cleanse(b, sizeof(mlkem1024));
            } else {
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

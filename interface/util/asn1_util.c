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
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
    0x04, 0x22, 0x80, 0x20, 0xbf, 0x4a, 0xea, 0x44, 0x28,
    0xe8, 0x70, 0xa4, 0x30, 0x3e, 0x86, 0xb9, 0x91, 0x71,
    0x57, 0x2b, 0x39, 0xe3, 0x2c, 0x5a, 0x52, 0x14, 0x26,
    0x46, 0xbd, 0xaf, 0x35, 0xd7, 0xaa, 0x6d, 0x78, 0x0c

}; // Seed at byte 22 for 32

static uint8_t mldsa65[] = {
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
    0x04, 0x22, 0x80, 0x20, 0x4a, 0xe7, 0xbe, 0x75, 0x55,
    0x37, 0xfc, 0x5c, 0xdf, 0xde, 0x52, 0xa6, 0x71, 0xc7,
    0x07, 0xdb, 0xc1, 0x84, 0x98, 0xc9, 0xb4, 0x41, 0xa3,
    0xe4, 0x3c, 0x92, 0x9a, 0xc6, 0x3e, 0x51, 0x5f, 0x13
};

static uint8_t mldsa87[] = {
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
    0x04, 0x22, 0x80, 0x20, 0x5b, 0x6a, 0x6d, 0x59, 0xaf,
    0x8b, 0x09, 0x18, 0xf6, 0x73, 0x9c, 0x86, 0xb3, 0x57,
    0x78, 0x1f, 0x90, 0x4f, 0x91, 0x71, 0x0a, 0x00, 0x70,
    0x0e, 0xa7, 0xf1, 0x34, 0xba, 0xb3, 0xd4, 0x3e, 0xec

};


static uint8_t mlkem512[] = {
    0x30, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01,
    0x04, 0x42, 0x80, 0x40, 0xa9, 0x9f, 0xb4, 0xeb, 0x19,
    0xf0, 0x71, 0x74, 0x2e, 0x77, 0x93, 0xc3, 0xdf, 0xf3,
    0x36, 0x3d, 0x76, 0x64, 0x41, 0x47, 0x55, 0x53, 0x26,
    0xf9, 0x0b, 0x33, 0x2b, 0x6a, 0x0b, 0x1e, 0x08, 0xca,
    0x60, 0x5e, 0x10, 0x87, 0x42, 0xa9, 0xa4, 0x16, 0xeb,
    0xec, 0x8f, 0xd2, 0x07, 0x4c, 0x63, 0xe6, 0xc1, 0x59,
    0x02, 0xbd, 0xf7, 0x03, 0x18, 0x81, 0xd0, 0x86, 0x18,
    0x5f, 0xaf, 0xa4, 0x53, 0x65

};

static uint8_t mlkem768[] = {
    0x30, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02,
    0x04, 0x42, 0x80, 0x40, 0xad, 0x8e, 0x66, 0x26, 0xf3,
    0x0e, 0xbb, 0x64, 0x5d, 0x46, 0x4f, 0x27, 0xe5, 0xd9,
    0x35, 0x5a, 0xc0, 0x33, 0x67, 0xfc, 0xc7, 0xaf, 0x7e,
    0x0b, 0xd8, 0x9e, 0x3d, 0xfb, 0x0a, 0xeb, 0x81, 0x25,
    0x04, 0xee, 0xef, 0x65, 0x16, 0xae, 0x75, 0xc4, 0x26,
    0xe4, 0x1b, 0xab, 0xb7, 0x15, 0x4f, 0xcd, 0x2a, 0xb4,
    0xce, 0x44, 0x90, 0xd1, 0x4a, 0x1c, 0xa7, 0x16, 0xed,
    0x59, 0x3e, 0x06, 0x84, 0x70
}; // Seed at byte 22 for 64


static uint8_t mlkem1024[] = {
    0x30, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03,
    0x04, 0x42, 0x80, 0x40, 0x63, 0xd5, 0x5c, 0xcf, 0x87,
    0x5f, 0x42, 0xd0, 0xf2, 0x5c, 0xee, 0xb5, 0x3e, 0x76,
    0x38, 0xef, 0x65, 0xb2, 0x32, 0x8b, 0xaf, 0x45, 0x27,
    0x10, 0x4d, 0x6d, 0x61, 0xb9, 0xe2, 0x7d, 0xeb, 0x4f,
    0x99, 0x3a, 0x0f, 0x33, 0xe9, 0x79, 0x15, 0x37, 0x11,
    0xa0, 0xdb, 0x9e, 0x5c, 0x3b, 0xf1, 0x9e, 0xb2, 0xcc,
    0xd0, 0x83, 0xbd, 0x4b, 0x5a, 0xa8, 0x16, 0x84, 0xb0,
    0x8e, 0xae, 0x48, 0xde, 0xe3

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

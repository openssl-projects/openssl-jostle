//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "asn1_util.h"


#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include "bc_err_codes.h"
#include "key_spec.h"
#include "ops.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"


//
// PrivateKeyInfo templates for ML-DSA / ML-KEM seed-only encoding.
// Used when the OpenSSL version being used does not natively support seed-only
// PKCS8 encoding for these algorithms. The seed bytes start at offset 22 in
// each template (32 bytes for ML-DSA, 64 bytes for ML-KEM); the dummy seed
// values get overwritten with the actual key's seed before BIO_write.
//
static const uint8_t mldsa44[] = {
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
    0x04, 0x22, 0x80, 0x20, 0xbf, 0x4a, 0xea, 0x44, 0x28,
    0xe8, 0x70, 0xa4, 0x30, 0x3e, 0x86, 0xb9, 0x91, 0x71,
    0x57, 0x2b, 0x39, 0xe3, 0x2c, 0x5a, 0x52, 0x14, 0x26,
    0x46, 0xbd, 0xaf, 0x35, 0xd7, 0xaa, 0x6d, 0x78, 0x0c
};

static const uint8_t mldsa65[] = {
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
    0x04, 0x22, 0x80, 0x20, 0x4a, 0xe7, 0xbe, 0x75, 0x55,
    0x37, 0xfc, 0x5c, 0xdf, 0xde, 0x52, 0xa6, 0x71, 0xc7,
    0x07, 0xdb, 0xc1, 0x84, 0x98, 0xc9, 0xb4, 0x41, 0xa3,
    0xe4, 0x3c, 0x92, 0x9a, 0xc6, 0x3e, 0x51, 0x5f, 0x13
};

static const uint8_t mldsa87[] = {
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
    0x04, 0x22, 0x80, 0x20, 0x5b, 0x6a, 0x6d, 0x59, 0xaf,
    0x8b, 0x09, 0x18, 0xf6, 0x73, 0x9c, 0x86, 0xb3, 0x57,
    0x78, 0x1f, 0x90, 0x4f, 0x91, 0x71, 0x0a, 0x00, 0x70,
    0x0e, 0xa7, 0xf1, 0x34, 0xba, 0xb3, 0xd4, 0x3e, 0xec
};

static const uint8_t mlkem512[] = {
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

static const uint8_t mlkem768[] = {
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
};

static const uint8_t mlkem1024[] = {
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


asn1_ctx *asn1_writer_allocate(int32_t *err) {
    asn1_ctx *ctx = OPENSSL_zalloc(sizeof(asn1_ctx));
    jo_assert(ctx != NULL);
    ctx->buffer = BIO_new(BIO_s_mem());
    jo_assert(ctx->buffer != NULL);
    *err = JO_SUCCESS;
    return ctx;
}

void asn1_writer_free(asn1_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
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
    jo_assert(ctx != NULL);
    jo_assert(ctx->buffer != NULL);
    uint8_t *buffer = NULL;

    long n = BIO_get_mem_data(ctx->buffer, &buffer);
    if (n < 0) {
        return JO_OPENSSL_ERROR;
    }
    *written = (size_t) n;

    if (output != NULL) {
        if (output_len != *written) {
            return JO_OUTPUT_OUT_OF_RANGE;
        }

        memcpy(output, buffer, *written);
    }

    return 1;
}


int32_t asn1_writer_encode_public_key(asn1_ctx *ctx, key_spec *key_spec, size_t *buf_len) {
    jo_assert(ctx != NULL);
    jo_assert(key_spec != NULL);
    jo_assert(key_spec->key != NULL);

    BIO_reset(ctx->buffer);
    ERR_clear_error();

    if (OPS_OPENSSL_ERROR_3 1 != i2d_PUBKEY_bio(ctx->buffer, key_spec->key)) {
        return 0;
    }

    long n = BIO_get_mem_data(ctx->buffer, NULL);
    if (n < 0) {
        return 0;
    }
    *buf_len = (size_t) n;

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
        int32_t ret = 0;
        memcpy(b, mldsa44, sizeof(mldsa44));

        if (
            OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
            goto cleanse_mldsa44;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mldsa44)) != (int) sizeof(mldsa44)) {
            goto cleanse_mldsa44;
        }
        ret = 1;
    cleanse_mldsa44:
        OPENSSL_cleanse(b, sizeof(b));
        return ret;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-65")) {
        uint8_t b[sizeof(mldsa65)];
        int32_t ret = 0;
        memcpy(b, mldsa65, sizeof(mldsa65));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
            goto cleanse_mldsa65;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mldsa65)) != (int) sizeof(mldsa65)) {
            goto cleanse_mldsa65;
        }
        ret = 1;
    cleanse_mldsa65:
        OPENSSL_cleanse(b, sizeof(b));
        return ret;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-DSA-87")) {
        uint8_t b[sizeof(mldsa87)];
        int32_t ret = 0;
        memcpy(b, mldsa87, sizeof(mldsa87));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_DSA_SEED, b + 22, 32, NULL)) {
            goto cleanse_mldsa87;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mldsa87)) != (int) sizeof(mldsa87)) {
            goto cleanse_mldsa87;
        }
        ret = 1;
    cleanse_mldsa87:
        OPENSSL_cleanse(b, sizeof(b));
        return ret;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-512")) {
        uint8_t b[sizeof(mlkem512)];
        int32_t ret = 0;
        memcpy(b, mlkem512, sizeof(mlkem512));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_KEM_SEED, b + 22, 64, NULL)) {
            goto cleanse_mlkem512;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mlkem512)) != (int) sizeof(mlkem512)) {
            goto cleanse_mlkem512;
        }
        ret = 1;
    cleanse_mlkem512:
        OPENSSL_cleanse(b, sizeof(b));
        return ret;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-768")) {
        uint8_t b[sizeof(mlkem768)];
        int32_t ret = 0;
        memcpy(b, mlkem768, sizeof(mlkem768));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_KEM_SEED, b + 22, 64, NULL)) {
            goto cleanse_mlkem768;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mlkem768)) != (int) sizeof(mlkem768)) {
            goto cleanse_mlkem768;
        }
        ret = 1;
    cleanse_mlkem768:
        OPENSSL_cleanse(b, sizeof(b));
        return ret;
    }

    if (EVP_PKEY_is_a(key_spec->key, "ML-KEM-1024")) {
        uint8_t b[sizeof(mlkem1024)];
        int32_t ret = 0;
        memcpy(b, mlkem1024, sizeof(mlkem1024));

        if (OPS_OPENSSL_ERROR_1
            1 != EVP_PKEY_get_octet_string_param(
                key_spec->key,
                OSSL_PKEY_PARAM_ML_KEM_SEED, b + 22, 64, NULL)) {
            goto cleanse_mlkem1024;
        }

        if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, sizeof(mlkem1024)) != (int) sizeof(mlkem1024)) {
            goto cleanse_mlkem1024;
        }
        ret = 1;
    cleanse_mlkem1024:
        OPENSSL_cleanse(b, sizeof(b));
        return ret;
    }

    // No algorithm matched — seed-only encoding only supports ML-DSA / ML-KEM.
    return JO_INCORRECT_KEY_TYPE;
}


int32_t asn1_writer_encode_private_key(asn1_ctx *ctx, key_spec *key_spec, size_t *buf_len, int encoding_option) {
    jo_assert(ctx != NULL);
    jo_assert(key_spec != NULL);
    jo_assert(key_spec->key != NULL);

    BIO_reset(ctx->buffer);
    ERR_clear_error();

    switch (encoding_option) {
        case PRIVATE_KEY_DEFAULT_ENCODING:
            if (OPS_OPENSSL_ERROR_4 !i2d_PrivateKey_bio(ctx->buffer, key_spec->key)) {
                return 0;
            }
            break;
        case PRIVATE_KEY_SEED_ONLY_ENCODING: {
            int32_t r = seed_only_encoder(ctx, key_spec);
            if (r != 1) {
                // r is either 0 (OpenSSL error) or a specific negative code
                // (e.g. JO_INCORRECT_KEY_TYPE for unsupported algorithm).
                return r;
            }
            break;
        }
        default:
            return 0;
    }


    long n = BIO_get_mem_data(ctx->buffer, NULL);
    if (n < 0) {
        return 0;
    }
    *buf_len = (size_t) n;

    return 1;
}


key_spec *asn1_writer_decode_private_key(const uint8_t *src, size_t src_len, int32_t *ret_code) {
    *ret_code = JO_FAIL;
    EVP_PKEY *new_key = NULL;

    if (src == NULL) {
        *ret_code = JO_INPUT_IS_NULL;
        return NULL;
    }

    if (OPS_INT32_OVERFLOW_1 src_len > INT32_MAX) {
        *ret_code = JO_INPUT_TOO_LONG_INT32;
        return NULL;
    }

    ERR_clear_error();

    const long _src_len = (int32_t) src_len;
    const uint8_t *_src = src;

    // Pass &new_key with new_key == NULL so d2i allocates fresh; on failure
    // it leaves *new_key NULL, avoiding the d2i-may-free-pre-alloc footgun.
    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    const EVP_PKEY *new_key_ = d2i_PrivateKey_ex(EVP_PKEY_NONE, &new_key, &_src, _src_len, libctx, NULL);

    if (new_key_ == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto err;
    }

    if (OPS_POINTER_CHANGE new_key != new_key_) {
        *ret_code = JO_UNEXPECTED_POINTER_CHANGE;
        goto err;
    }


    key_spec *key = OPENSSL_zalloc(sizeof(key_spec));
    jo_assert(key != NULL);

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

    if (OPS_INT32_OVERFLOW_1 src_len > INT32_MAX) {
        *ret_code = JO_INPUT_TOO_LONG_INT32;
        return NULL;
    }

    ERR_clear_error();

    const long _src_len = (int32_t) src_len;
    const uint8_t *_src = src;

    // Pass &new_key with new_key == NULL so d2i allocates fresh; on failure
    // it leaves *new_key NULL, avoiding the d2i-may-free-pre-alloc footgun.
    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    const EVP_PKEY *new_key_ = d2i_PUBKEY_ex(&new_key, &_src, _src_len, libctx, NULL);

    if (new_key_ == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto err;
    }

    if (OPS_POINTER_CHANGE new_key != new_key_) {
        *ret_code = JO_UNEXPECTED_POINTER_CHANGE;
        goto err;
    }

    key_spec *key = OPENSSL_zalloc(sizeof(key_spec));
    jo_assert(key != NULL);

    key->key = new_key;

    *ret_code = JO_SUCCESS;
    return key;

err:
    EVP_PKEY_free(new_key);
    return NULL;
}

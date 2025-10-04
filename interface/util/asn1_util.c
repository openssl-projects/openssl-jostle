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

int32_t asn1_writer_encode_private_key(asn1_ctx *ctx, key_spec *key_spec, size_t *buf_len) {
    assert(ctx != NULL);
    assert(key_spec != NULL);
    assert(key_spec->key != NULL);

    if (!i2d_PrivateKey_bio(ctx->buffer, key_spec->key)) {
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

    const uint8_t *_src = src;

    new_key = EVP_PKEY_new();

    const EVP_PKEY *new_key_ = d2i_PrivateKey(EVP_PKEY_NONE, &new_key, &_src, (long) src_len);

    if (new_key_ == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto err;
    }

    if (OPS_POINTER_CHANGE new_key != new_key_) {
        *ret_code = JO_UNEXPECTED_POINTER_CHANGE;
        goto err;
    }



    // // TODO return string name from OpenSSL and use a hash table on java side to map it to an key type enum
    //
    // if (EVP_PKEY_is_a(new_key, "ML-DSA-44"))
    //     spec_type = KS_MLDSA_44;
    // else if (EVP_PKEY_is_a(new_key, "ML-DSA-65"))
    //     spec_type = KS_MLDSA_65;
    // else if (EVP_PKEY_is_a(new_key, "ML-DSA-87"))
    //     spec_type = KS_MLDSA_87;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-128s"))
    //     spec_type = KS_SLH_DSA_SHA2_128s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-128f"))
    //     spec_type = KS_SLH_DSA_SHA2_128f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-192s"))
    //     spec_type = KS_SLH_DSA_SHA2_192s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-192f"))
    //     spec_type = KS_SLH_DSA_SHA2_192f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-256s"))
    //     spec_type = KS_SLH_DSA_SHA2_256s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-256f"))
    //     spec_type = KS_SLH_DSA_SHA2_256f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-128s"))
    //     spec_type = KS_SLH_DSA_SHAKE_128s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-128f"))
    //     spec_type = KS_SLH_DSA_SHAKE_128f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-192s"))
    //     spec_type = KS_SLH_DSA_SHAKE_192s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-192f"))
    //     spec_type = KS_SLH_DSA_SHAKE_192f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-256s"))
    //     spec_type = KS_SLH_DSA_SHAKE_256s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-256f"))
    //     spec_type = KS_SLH_DSA_SHAKE_256f;
    // else if (EVP_PKEY_is_a(new_key, "ML-KEM-512"))
    //     spec_type = KS_ML_KEM_512;
    // else if (EVP_PKEY_is_a(new_key, "ML-KEM-768"))
    //     spec_type = KS_ML_KEM_768;
    // else if (EVP_PKEY_is_a(new_key, "ML-KEM-1024"))
    //     spec_type = KS_ML_KEM_1024;
    // else {
    //     *ret_code = JO_UNKNOWN_OSSL_KEY_TYPE;
    //     goto err;
    // }


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

    new_key = EVP_PKEY_new();

    const uint8_t *_src = src;

    const EVP_PKEY *new_key_ = d2i_PUBKEY(&new_key, &_src, (long) &src_len);

    if (new_key_ == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto err;
    }

    if (OPS_POINTER_CHANGE new_key != new_key_) {
        *ret_code = JO_UNEXPECTED_POINTER_CHANGE;
        goto err;
    }



    // TODO return string name from OpenSSL and use a hash table on java side to map it to an key type enum

    // if (EVP_PKEY_is_a(new_key, "ML-DSA-44"))
    //     spec_type = KS_MLDSA_44;
    // else if (EVP_PKEY_is_a(new_key, "ML-DSA-65"))
    //     spec_type = KS_MLDSA_65;
    // else if (EVP_PKEY_is_a(new_key, "ML-DSA-87"))
    //     spec_type = KS_MLDSA_87;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-128s"))
    //     spec_type = KS_SLH_DSA_SHA2_128s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-128f"))
    //     spec_type = KS_SLH_DSA_SHA2_128f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-192s"))
    //     spec_type = KS_SLH_DSA_SHA2_192s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-192f"))
    //     spec_type = KS_SLH_DSA_SHA2_192f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-256s"))
    //     spec_type = KS_SLH_DSA_SHA2_256s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHA2-256f"))
    //     spec_type = KS_SLH_DSA_SHA2_256f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-128s"))
    //     spec_type = KS_SLH_DSA_SHAKE_128s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-128f"))
    //     spec_type = KS_SLH_DSA_SHAKE_128f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-192s"))
    //     spec_type = KS_SLH_DSA_SHAKE_192s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-192f"))
    //     spec_type = KS_SLH_DSA_SHAKE_192f;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-256s"))
    //     spec_type = KS_SLH_DSA_SHAKE_256s;
    // else if (EVP_PKEY_is_a(new_key, "SLH-DSA-SHAKE-256f"))
    //     spec_type = KS_SLH_DSA_SHAKE_256f;
    // else if (EVP_PKEY_is_a(new_key, "ML-KEM-512"))
    //     spec_type = KS_ML_KEM_512;
    // else if (EVP_PKEY_is_a(new_key, "ML-KEM-768"))
    //     spec_type = KS_ML_KEM_768;
    // else if (EVP_PKEY_is_a(new_key, "ML-KEM-1024"))
    //     spec_type = KS_ML_KEM_1024;
    // else {
    //     *ret_code = JO_UNKNOWN_OSSL_KEY_TYPE;
    //     goto err;
    // }


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

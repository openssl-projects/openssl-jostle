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
#include <openssl/encoder.h>
#include "bc_err_codes.h"
#include "dh.h"
#include "key_spec.h"
#include "ops.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"


//
// Seed-only PrivateKeyInfo: an RFC 5958 OneAsymmetricKey whose privateKey holds the [0] IMPLICIT seed of
// RFC 9881 (ML-DSA, 32 bytes) or RFC 9935 (ML-KEM, 64 bytes); the seed follows the SEED_OFFSET header bytes.
//
#define SEED_OFFSET 22
#define MAX_SEED_LEN 64

typedef struct {
    const char *name;
    const char *seed_param;
    size_t seed_len;
    uint8_t header[SEED_OFFSET];
} seed_only_form;

static const seed_only_form seed_only_forms[] = {
    {"ML-DSA-44", OSSL_PKEY_PARAM_ML_DSA_SEED, 32, {
        0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11, 0x04, 0x22, 0x80, 0x20}},
    {"ML-DSA-65", OSSL_PKEY_PARAM_ML_DSA_SEED, 32, {
        0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12, 0x04, 0x22, 0x80, 0x20}},
    {"ML-DSA-87", OSSL_PKEY_PARAM_ML_DSA_SEED, 32, {
        0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13, 0x04, 0x22, 0x80, 0x20}},
    {"ML-KEM-512", OSSL_PKEY_PARAM_ML_KEM_SEED, 64, {
        0x30, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01, 0x04, 0x42, 0x80, 0x40}},
    {"ML-KEM-768", OSSL_PKEY_PARAM_ML_KEM_SEED, 64, {
        0x30, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02, 0x04, 0x42, 0x80, 0x40}},
    {"ML-KEM-1024", OSSL_PKEY_PARAM_ML_KEM_SEED, 64, {
        0x30, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03, 0x04, 0x42, 0x80, 0x40}},
};


asn1_ctx *asn1_writer_allocate(int32_t *err) {
    asn1_ctx *ctx = OPENSSL_zalloc(sizeof(asn1_ctx));
    jo_assert(ctx != NULL);
    ctx->buffer = BIO_new(BIO_s_mem());
    jo_assert(ctx->buffer != NULL);
    *err = JO_SUCCESS;
    JO_LEDGER_CREATED(JO_LEDGER_ASN1_CTX);
    return ctx;
}

void asn1_writer_free(asn1_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    JO_LEDGER_DESTROYED(JO_LEDGER_ASN1_CTX);
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

        // A freshly-allocated / reset mem BIO reports buffer == NULL with
        // n == 0; memcpy(dst, NULL, 0) is undefined behaviour even for a
        // zero length, so only copy when there is something to copy.
        if (*written > 0) {
            memcpy(output, buffer, *written);
        }
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
 * Writes the seed-only form of an ML-DSA or ML-KEM key.
 * Returns 1, 0 when the write fails, JO_INVALID_SEED_LEN when the key has no seed of the form's length (an
 * expanded-only import), or JO_INCORRECT_KEY_TYPE for any other algorithm.
 */
static int32_t seed_only_encoder(asn1_ctx *ctx, key_spec *key_spec) {
    const seed_only_form *form = NULL;
    for (size_t i = 0; i < sizeof(seed_only_forms) / sizeof(seed_only_forms[0]); i++) {
        if (EVP_PKEY_is_a(key_spec->key, seed_only_forms[i].name)) {
            form = &seed_only_forms[i];
            break;
        }
    }
    if (form == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    uint8_t b[SEED_OFFSET + MAX_SEED_LEN];
    const size_t len = SEED_OFFSET + form->seed_len;
    size_t seed_len = 0;
    int32_t ret = 0;
    memcpy(b, form->header, SEED_OFFSET);

    // A short seed would leave stale bytes in the encoding.
    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_get_octet_string_param(
            key_spec->key, form->seed_param, b + SEED_OFFSET, form->seed_len, &seed_len)) {
        ret = JO_INVALID_SEED_LEN;
        goto exit;
    }
    if (seed_len != form->seed_len) {
        ret = JO_INVALID_SEED_LEN;
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 BIO_write(ctx->buffer, b, (int) len) != (int) len) {
        goto exit;
    }
    ret = 1;

exit:
    OPENSSL_cleanse(b, sizeof(b));
    return ret;
}


/**
 * Emit a private key as PKCS#8 PrivateKeyInfo via OSSL_ENCODER. Used
 * for EC keys where {@code i2d_PrivateKey_bio} would otherwise emit
 * the legacy SEC1 ECPrivateKey form (which a strict third-party
 * parser like BC's EC KeyFactory rejects, and which is also a
 * contract violation since {@code JOECPrivateKey.getFormat()}
 * returns "PKCS#8").
 *
 * Returns 1 on success, 0 on OpenSSL error.
 */
static int32_t encode_private_key_pkcs8(asn1_ctx *ctx, key_spec *key_spec) {
    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(
            key_spec->key,
            EVP_PKEY_KEYPAIR,
            "DER",
            "PrivateKeyInfo",
            NULL);
    if (ectx == NULL) {
        return 0;
    }
    int32_t ok = OSSL_ENCODER_to_bio(ectx, ctx->buffer);
    OSSL_ENCODER_CTX_free(ectx);
    return ok ? 1 : 0;
}


int32_t asn1_writer_encode_private_key(asn1_ctx *ctx, key_spec *key_spec, size_t *buf_len, int encoding_option) {
    jo_assert(ctx != NULL);
    jo_assert(key_spec != NULL);
    jo_assert(key_spec->key != NULL);

    BIO_reset(ctx->buffer);
    ERR_clear_error();

    switch (encoding_option) {
        case PRIVATE_KEY_DEFAULT_ENCODING:
            // EC, RSA, DSA and DH keys go through the OSSL_ENCODER PKCS#8 path so the
            // emitted bytes are an actual PKCS#8 PrivateKeyInfo (matching
            // getFormat()="PKCS#8") rather than the "traditional" form that
            // i2d_PrivateKey_bio defaults to — SEC1 ECPrivateKey for EC, and
            // the PKCS#1 RSAPrivateKey for RSA. Ed25519/Ed448 and the PQC
            // types have no traditional form, so i2d_PrivateKey already emits
            // PKCS#8 for them and they stay on the legacy path.
            if (EVP_PKEY_is_a(key_spec->key, "EC")
                || EVP_PKEY_is_a(key_spec->key, "RSA")
                || EVP_PKEY_is_a(key_spec->key, "DSA")
                || EVP_PKEY_is_a(key_spec->key, "DH")
                || EVP_PKEY_is_a(key_spec->key, "DHX")) {
                if (OPS_OPENSSL_ERROR_4 1 != encode_private_key_pkcs8(ctx, key_spec)) {
                    return 0;
                }
                break;
            }
            if (OPS_OPENSSL_ERROR_4 1 != i2d_PrivateKey_bio(ctx->buffer, key_spec->key)) {
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
    OSSL_LIB_CTX *libctx = get_global_jostle_fips_ossl_lib_ctx();
    const EVP_PKEY *new_key_ = d2i_PrivateKey_ex(EVP_PKEY_NONE, &new_key, &_src, _src_len, libctx, NULL);

    if (new_key_ == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto err;
    }

    if (OPS_POINTER_CHANGE new_key != new_key_) {
        *ret_code = JO_UNEXPECTED_POINTER_CHANGE;
        goto err;
    }

    // d2i consumes exactly one TLV and advances _src past it. Anything
    // left over is trailing garbage after a well-formed PKCS#8 blob —
    // reject it (strict parsers do; silently accepting can mask
    // corruption).
    if ((size_t) (_src - src) != src_len) {
        *ret_code = JO_DER_TRAILING_DATA;
        goto err;
    }

    // A DHX private key carries its public half; it gets the public decode's subgroup check.
    if (EVP_PKEY_is_a(new_key, "DHX")) {
        int32_t subgroup_check = dh_validate_public_key_subgroup(new_key);
        if (subgroup_check != JO_SUCCESS) {
            *ret_code = subgroup_check;
            goto err;
        }
    }

    key_spec *key = create_spec();
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
    OSSL_LIB_CTX *libctx = get_global_jostle_fips_ossl_lib_ctx();
    const EVP_PKEY *new_key_ = d2i_PUBKEY_ex(&new_key, &_src, _src_len, libctx, NULL);

    if (new_key_ == NULL) {
        *ret_code = JO_OPENSSL_ERROR;
        goto err;
    }

    if (OPS_POINTER_CHANGE new_key != new_key_) {
        *ret_code = JO_UNEXPECTED_POINTER_CHANGE;
        goto err;
    }

    // d2i consumes exactly one TLV and advances _src past it. Anything
    // left over is trailing garbage after a well-formed SPKI blob —
    // reject it (strict parsers do; silently accepting can mask
    // corruption).
    if ((size_t) (_src - src) != src_len) {
        *ret_code = JO_DER_TRAILING_DATA;
        goto err;
    }

    // A DH or DHX key decoded here never reaches dh_make_public_from_components, so this is its own call
    // site for the same checks: the range for both, the subgroup when q is present.
    if (EVP_PKEY_is_a(new_key, "DHX") || EVP_PKEY_is_a(new_key, "DH")) {
        int32_t subgroup_check = dh_validate_public_key_subgroup(new_key);
        if (subgroup_check != JO_SUCCESS) {
            *ret_code = subgroup_check;
            goto err;
        }
    }

    key_spec *key = create_spec();
    key->key = new_key;

    *ret_code = JO_SUCCESS;
    return key;

err:
    EVP_PKEY_free(new_key);
    return NULL;
}

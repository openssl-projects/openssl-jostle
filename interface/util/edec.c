//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#include "edec.h"


#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "key_spec.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

int32_t edec_generate_key(key_spec *spec, int32_t type, void *rnd_src) {
    jo_assert(spec != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    switch (type) {
        case KS_ED25519:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "ED25519",NULL);
            break;
        case KS_ED448:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "ED448",NULL);
            break;
        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }

    if (ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (!EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (!EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_1 0) {
        EVP_PKEY_free(spec->key);
        spec->key = NULL;
    }
#endif

    if (spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}

int32_t edec_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    size_t min_len;

    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    ERR_clear_error();

    const char *algo = EVP_PKEY_get0_type_name(key_spec->key);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    // OpenSSL returns "ED25519" / "ED448" (uppercase) from EVP_PKEY_get0_type_name.
    if (strcmp(algo, "ED25519") != 0 && strcmp(algo, "ED448") != 0) {
        return JO_INCORRECT_KEY_TYPE;
    }


    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                                                 &min_len)) {
        return JO_OPENSSL_ERROR;
    }


    if (out == NULL) {
        return (int32_t) min_len;
    }


    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, min_len,
                                                                 &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1000);
    }

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t edec_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    size_t min_len;

    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    ERR_clear_error();

    const char *algo = EVP_PKEY_get0_type_name(key_spec->key);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    // OpenSSL returns "ED25519" / "ED448" (uppercase) from EVP_PKEY_get0_type_name.
    if (strcmp(algo, "ED25519") != 0 && strcmp(algo, "ED448") != 0) {
        return JO_INCORRECT_KEY_TYPE;
    }

    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0,
                                                                 &min_len)) {
        return JO_OPENSSL_ERROR;
    }


    if (out == NULL) {
        return (int32_t) min_len;
    }

    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, out, min_len,
                                                                 &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1000);
    }

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t edec_decode_private_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    size_t min_len = 0;
    const char *type;

    jo_assert(key_spec != NULL);

    /*
        * KeyFactory has not been initialized to expect a certain key type
        * so attempt to use length to determine ED private key type
        */

    if (typeId == KS_NONE) {
        switch (src_len) {
            case 32:
                typeId = KS_ED25519;
                break;
            case 57:
                typeId = KS_ED448;
                break;
            default:
                ret_code = JO_UNKNOWN_KEY_LEN;
                goto exit;
        }
    }


    switch (typeId) {
        case KS_ED25519:
            min_len = 32;
            type = "Ed25519";
            break;
        case KS_ED448:
            min_len = 57;
            type = "Ed448";
            break;

        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }


    if (min_len != src_len) {
        ret_code = JO_ENCODED_PRIVATE_KEY_LEN;
        goto exit;
    }

    ERR_clear_error();

    key_spec->key = EVP_PKEY_new_raw_private_key_ex(
        get_global_jostle_ossl_lib_ctx(), type,NULL, src, src_len);

#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_1 0) {
        EVP_PKEY_free(key_spec->key);
        key_spec->key = NULL;
        // trigger the openssl error pathway below
    }
#endif

    if (key_spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    return ret_code;
}

int32_t edec_decode_public_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    size_t min_len = 0;
    const char *type = NULL;

    jo_assert(key_spec != NULL);


    /*
     * KeyFactory has not been initialized to expect a certain key type
     * so attempt to use length to determine ML-DSA public key type
     */
    if (typeId == KS_NONE) {
        switch (src_len) {
            case 32:
                typeId = KS_ED25519;
                break;
            case 57:
                typeId = KS_ED448;
                break;
            default:
                ret_code = JO_UNKNOWN_KEY_LEN;
                goto exit;
        }
    }


    switch (typeId) {
        case KS_ED25519:
            min_len = 32;
            type = "Ed25519";
            break;
        case KS_ED448:
            min_len = 57;
            type = "Ed448";
            break;

        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }

    if (min_len != src_len) {
        ret_code = JO_ENCODED_PUBLIC_KEY_LEN;
        goto exit;
    }

    ERR_clear_error();

    key_spec->key = EVP_PKEY_new_raw_public_key_ex(
        get_global_jostle_ossl_lib_ctx(), type,NULL, src, src_len);

#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_1 0) {
        EVP_PKEY_free(key_spec->key);
        key_spec->key = NULL;
        // trigger the openssl error pathway below
    }

#endif


    if (key_spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    return ret_code;
}


edec_ctx *edec_ctx_create(int32_t *err) {
    jo_assert(err != NULL);

    edec_ctx *ctx = (edec_ctx *) OPENSSL_zalloc(sizeof(edec_ctx));
    jo_assert(ctx != NULL);

    ERR_clear_error();
    ctx->message = BIO_new(BIO_s_mem());
    if (OPS_OPENSSL_ERROR_1 ctx->message == NULL) {
        *err = JO_OPENSSL_ERROR;
        OPENSSL_free(ctx);
        return NULL;
    }

    jo_assert(ctx->message != NULL);

    *err = JO_SUCCESS;
    return ctx;
}

void edec_ctx_destroy(edec_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->message != NULL) {
        BIO_reset(ctx->message);
        BIO_free_all(ctx->message);
    }

    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
    }

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

int32_t edec_ctx_init_sign(
    edec_ctx *ctx,
    const key_spec *key_spec,
    const char *name,
    int name_len,
    const uint8_t *context, int32_t context_len, void *rnd_src) {
    jo_assert(ctx != NULL);
    jo_assert(key_spec != NULL);
    jo_assert(name != NULL);
    jo_assert(name_len > 0);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }


    BIO_reset(ctx->message);
    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
    }

    ctx->digest_ctx = EVP_MD_CTX_new();

    if (OPS_OPENSSL_ERROR_1 ctx->digest_ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1000);
        goto exit;
    }

    if (context == NULL) {
        context_len = 0;
    }


    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("instance", (void*)name, name_len),
        OSSL_PARAM_END,
        OSSL_PARAM_END
    };

    if (context != NULL) {
        params[1] = OSSL_PARAM_construct_octet_string("context-string", (void *) context, context_len);
    }


    if (OPS_OPENSSL_ERROR_2 EVP_DigestSignInit_ex(ctx->digest_ctx, NULL, NULL, libctx, NULL, key_spec->key,
                                                  params) != 1) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1001);
        goto exit;
    }

    ctx->opp = EDEC_SIGN;

    ret_code = JO_SUCCESS;

exit:
    return ret_code;
}


int32_t edec_ctx_init_verify(
    edec_ctx *ctx,
    const key_spec *key_spec,
    const char *name,
    int name_len,
    const uint8_t *context, int32_t context_len) {
    jo_assert(ctx != NULL);
    jo_assert(key_spec != NULL);
    jo_assert(name_len >0);
    jo_assert(name != NULL);


    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    BIO_reset(ctx->message);
    if (ctx->digest_ctx != NULL) {
        EVP_MD_CTX_free(ctx->digest_ctx);
    }

    ctx->digest_ctx = EVP_MD_CTX_new();

    if (OPS_OPENSSL_ERROR_1 ctx->digest_ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(1003);
        goto exit;
    }

    if (context == NULL) {
        context_len = 0;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("instance", (void*)name, name_len),
        OSSL_PARAM_END,
        OSSL_PARAM_END
    };

    if (context != NULL) {
        params[1] = OSSL_PARAM_construct_octet_string("context-string", (void *) context, context_len);
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_DigestVerifyInit_ex(
            ctx->digest_ctx,
            NULL,
            NULL,
            libctx,
            NULL,
            key_spec->key, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(1004);
        goto exit;
    }

    ctx->opp = EDEC_VERIFY;

    ret_code = JO_SUCCESS;

exit:
    return ret_code;
}


int32_t edec_ctx_update(edec_ctx *ctx, const uint8_t *in, const size_t in_len) {
    jo_assert(ctx != NULL);
    jo_assert(in != NULL);

    if (ctx->digest_ctx == NULL) {
        return JO_NOT_INITIALIZED;
    }

    if (in_len > (size_t) INT_MAX) {
        return JO_INPUT_TOO_LONG_INT32;
    }

    ERR_clear_error();
    if (BIO_write(ctx->message, in, (int) in_len) != (int) in_len) {
        return JO_OPENSSL_ERROR;
    }

    return JO_SUCCESS;
}


int32_t edec_ctx_sign(edec_ctx *ctx, uint8_t *out, const size_t out_len, void *rnd_src) {
    jo_assert(ctx != NULL);
    int ret_code = JO_FAIL;
    int sign_attempted = 0;

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    if (ctx->digest_ctx == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (ctx->opp != EDEC_SIGN) {
        ret_code = JO_UNEXPECTED_STATE;
        goto exit;
    }

    uint8_t *msg = NULL;
    const long raw_msg_len = BIO_get_mem_data(ctx->message, &msg);
    if (raw_msg_len < 0) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }
    const size_t msg_len = (size_t) raw_msg_len;

    size_t sig_len = 0;
    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    if (OPS_OPENSSL_ERROR_1 1 != EVP_DigestSign(ctx->digest_ctx, NULL, &sig_len, msg, msg_len)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }


    if (OPS_INT32_OVERFLOW_1 sig_len > INT32_MAX) {
        ret_code = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }

    if (out != NULL) {
        if (sig_len > out_len) {
            // recoverable — caller may retry with a larger buffer; do not reset BIO
            ret_code = JO_OUTPUT_TOO_SMALL;
            goto exit;
        }


        const size_t sig_len_ = sig_len;

        rand_set_java_srand_call(rnd_src);
        sign_attempted = 1;

        if (OPS_OPENSSL_ERROR_2 EVP_DigestSign(ctx->digest_ctx, out, &sig_len, msg, msg_len) != 1) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;
        }


        if (OPS_LEN_CHANGE_1 sig_len_ != sig_len) {
            ret_code = JO_UNEXPECTED_SIG_LEN_CHANGE;
            goto exit;
        }
    }

    ret_code = (int32_t) sig_len;

exit:
    // BIO holds the buffered message. Once the actual signature write has been attempted
    // (success or failure), the operation is complete and the message must not leak into
    // the next sign call. Caller must re-initialise to retry after a sign failure.
    if (sign_attempted) {
        BIO_reset(ctx->message);
    }
    return ret_code;
}

int32_t edec_ctx_verify(edec_ctx *ctx, const uint8_t *sig, const size_t sig_len) {
    jo_assert(ctx != NULL);
    int ret_code = JO_FAIL;

    if (ctx->digest_ctx == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (ctx->opp != EDEC_VERIFY) {
        ret_code = JO_UNEXPECTED_STATE;
        goto exit;
    }

    ERR_clear_error();

    // OpenSSL emits an "invalid signature" error on verify-fail which we don't care about.
    // Set a mark so we can selectively discard that noise without losing genuine errors
    // (real OpenSSL failures need to remain queued for the caller to format).
    ERR_set_mark();

    uint8_t *msg = NULL;
    const long raw_msg_len = BIO_get_mem_data(ctx->message, &msg);
    if (raw_msg_len < 0) {
        ERR_clear_last_mark();
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }
    const size_t msg_len = (size_t) raw_msg_len;
    int ret = EVP_DigestVerify(ctx->digest_ctx, sig, sig_len, msg, msg_len);
    BIO_reset(ctx->message);

    if (OPS_OPENSSL_ERROR_1 0) {
        ret = -1;
    }

    if (ret == 1) {
        ERR_pop_to_mark();         // success — drop any spurious errors above the mark
        ret_code = JO_SUCCESS;
    } else if (ret == 0) {
        ERR_pop_to_mark();         // bad signature — drop the "invalid signature" noise
        ret_code = JO_FAIL;
    } else {
        ERR_clear_last_mark();     // real OpenSSL error — keep queue, just drop the mark
        ret_code = JO_OPENSSL_ERROR;
    }

exit:
    return ret_code;
}

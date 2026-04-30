//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "slhdsa.h"


#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "bc_err_codes.h"
#include "key_spec.h"
#include "ops.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"

inline int32_t get_n(const int key_type) {
    switch (key_type) {
        case KS_SLH_DSA_SHA2_128f:
        case KS_SLH_DSA_SHA2_128s:
        case KS_SLH_DSA_SHAKE_128f:
        case KS_SLH_DSA_SHAKE_128s:
            return 16;

        case KS_SLH_DSA_SHA2_192f:
        case KS_SLH_DSA_SHA2_192s:
        case KS_SLH_DSA_SHAKE_192s:
        case KS_SLH_DSA_SHAKE_192f:
            return 24;

        case KS_SLH_DSA_SHA2_256f:
        case KS_SLH_DSA_SHA2_256s:
        case KS_SLH_DSA_SHAKE_256f:
        case KS_SLH_DSA_SHAKE_256s:
            return 32;

        default:
            return -1;
    }
}


int32_t slh_dsa_generate_key_pair(key_spec *spec, int32_t type, uint8_t *seed, size_t seed_len, void *rand_src) {
    jo_assert(spec != NULL);

    if (rand_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    rand_set_java_srand_call(rand_src);

    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    const int32_t slh_n = get_n(type);

    if (slh_n <= 0) {
        ret_code = JO_INCORRECT_KEY_TYPE;
        goto exit;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_END,
        OSSL_PARAM_END
    };

    if (seed != NULL) {
        if (seed_len != 3 * (size_t) slh_n) {
            // slh_n not negative by this point
            ret_code = JO_INVALID_SEED_LEN;
            goto exit;
        }
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, seed, seed_len);
    }

    switch (type) {
        case KS_SLH_DSA_SHA2_128f:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHA2-128F",NULL);
            break;
        case KS_SLH_DSA_SHA2_128s:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHA2-128S",NULL);
        break;
        case KS_SLH_DSA_SHA2_192f:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHA2-192F",NULL);
            break;
        case KS_SLH_DSA_SHA2_192s:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHA2-192S",NULL);
            break;
        case KS_SLH_DSA_SHA2_256f:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHA2-256F",NULL);
            break;
        case KS_SLH_DSA_SHA2_256s:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHA2-256S",NULL);
            break;
        case KS_SLH_DSA_SHAKE_128f:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHAKE-128F",NULL);
            break;
        case KS_SLH_DSA_SHAKE_128s:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHAKE-128S",NULL);
            break;
        case KS_SLH_DSA_SHAKE_192f:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHAKE-192F",NULL);
            break;
        case KS_SLH_DSA_SHAKE_192s:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHAKE-192S",NULL);
            break;
        case KS_SLH_DSA_SHAKE_256f:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHAKE-256F",NULL);
            break;
        case KS_SLH_DSA_SHAKE_256s:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "SLH-DSA-SHAKE-256S",NULL);
            break;
        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }


    if (OPS_OPENSSL_ERROR_3 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(2100);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 !EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(2101);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_5 !EVP_PKEY_CTX_set_params(ctx, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(2102);
        goto exit;
    }

    // Defensive: caller is expected to pass a fresh spec, but if the spec
    // already holds a key, EVP_PKEY_keygen would overwrite it without freeing
    // and leak the EVP_PKEY. Mirrors the same guard in decode_*_key.
    if (spec->key != NULL) {
        EVP_PKEY_free(spec->key);
        spec->key = NULL;
    }

    if (OPS_OPENSSL_ERROR_6 !EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(2103);
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

int32_t slh_dsa_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    jo_assert(key_spec != NULL);
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    const char *algo = EVP_PKEY_get0_type_name(pkey);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    if (0 != strncmp(algo, "SLH-DSA", 7)) {
        return JO_INCORRECT_KEY_TYPE;
    }

    ERR_clear_error();

    size_t min_len;

    if (OPS_OPENSSL_ERROR_1 !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &min_len)) {
        return JO_OPENSSL_ERROR;
    }

    // Guard the size-query cast: every later return casts min_len (or written,
    // which is bounded by min_len) to int32_t.
    if (OPS_INT32_OVERFLOW_1 min_len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    if (out == NULL) {
        return (int32_t) min_len;
    }


    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_2 !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, min_len, &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET(1000);
    }

    return (int32_t) written;
}

int32_t slh_dsa_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    jo_assert(key_spec != NULL);
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    const char *algo = EVP_PKEY_get0_type_name(pkey);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    if (0 != strncmp(algo, "SLH-DSA", 7)) {
        return JO_INCORRECT_KEY_TYPE;
    }

    ERR_clear_error();

    size_t min_len;

    if (OPS_OPENSSL_ERROR_1 !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &min_len)) {
        return JO_OPENSSL_ERROR;
    }

    // Guard the size-query cast: every later return casts min_len (or written,
    // which is bounded by min_len) to int32_t.
    if (OPS_INT32_OVERFLOW_1 min_len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    if (out == NULL) {
        return (int32_t) min_len;
    }

    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;


    if (OPS_OPENSSL_ERROR_2 !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, out, min_len, &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET(1000);
    }

    return (int32_t) written;
}

int32_t slh_dsa_get_private_seed(key_spec *key_spec, uint8_t *out, size_t out_len) {
    jo_assert(key_spec != NULL);
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    const char *algo = EVP_PKEY_get0_type_name(pkey);
    if (algo == NULL) {
        return JO_INCORRECT_KEY_TYPE;
    }

    if (0 != strncmp(algo, "SLH-DSA", 7)) {
        return JO_INCORRECT_KEY_TYPE;
    }

    ERR_clear_error();

    size_t min_len;

    if (OPS_OPENSSL_ERROR_1
        !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_SLH_DSA_SEED, NULL, 0, &min_len)) {
        return JO_OPENSSL_ERROR;
    }

    // Guard the size-query cast: every later return casts min_len (or written,
    // which is bounded by min_len) to int32_t.
    if (OPS_INT32_OVERFLOW_1 min_len > INT32_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    if (out == NULL) {
        return (int32_t) min_len;
    }


    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_2
        !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_SLH_DSA_SEED, out, min_len, &written)) {
        return JO_OPENSSL_ERROR OPS_OFFSET(1000);
    }

    return (int32_t) written;
}

int32_t slh_dsa_decode_private_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    const char *type;

    jo_assert(key_spec != NULL);

    const int slh_n = get_n(typeId);
    if (slh_n <= 0) {
        return JO_INCORRECT_KEY_TYPE;
    }

    const size_t min_len = (size_t) slh_n * 4;

    switch (typeId) {
        case KS_SLH_DSA_SHA2_128f:
            type = "SLH-DSA-SHA2-128F";
            break;
        case KS_SLH_DSA_SHA2_128s:
            type = "SLH-DSA-SHA2-128S";
            break;
        case KS_SLH_DSA_SHAKE_128f:
            type = "SLH-DSA-SHAKE-128F";
            break;
        case KS_SLH_DSA_SHAKE_128s:
            type = "SLH-DSA-SHAKE-128S";
            break;

        case KS_SLH_DSA_SHA2_192f:
            type = "SLH-DSA-SHA2-192F";
            break;
        case KS_SLH_DSA_SHA2_192s:
            type = "SLH-DSA-SHA2-192S";
            break;
        case KS_SLH_DSA_SHAKE_192s:
            type = "SLH-DSA-SHAKE-192S";
            break;
        case KS_SLH_DSA_SHAKE_192f:
            type = "SLH-DSA-SHAKE-192F";
            break;
        case KS_SLH_DSA_SHA2_256f:
            type = "SLH-DSA-SHA2-256F";
            break;
        case KS_SLH_DSA_SHA2_256s:
            type = "SLH-DSA-SHA2-256S";
            break;
        case KS_SLH_DSA_SHAKE_256f:
            type = "SLH-DSA-SHAKE-256F";
            break;
        case KS_SLH_DSA_SHAKE_256s:
            type = "SLH-DSA-SHAKE-256S";
            break;
        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }


    if (src_len != ((size_t) slh_n * 3) && min_len != src_len) {
        // slh_n not negative by this point
        ret_code = JO_ENCODED_PRIVATE_KEY_LEN;
        goto exit;
    }

    ERR_clear_error();

    // Defensive: caller is expected to pass a fresh spec, but if the spec
    // already holds a key, dropping it on the floor would leak the EVP_PKEY.
    if (key_spec->key != NULL) {
        EVP_PKEY_free(key_spec->key);
        key_spec->key = NULL;
    }

    key_spec->key = EVP_PKEY_new_raw_private_key_ex(get_global_jostle_ossl_lib_ctx(), type,NULL, src, src_len);

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

int32_t slh_dsa_decode_public_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    const char *type;

    jo_assert(key_spec != NULL);

    const int slh_n = get_n(typeId);
    if (slh_n <= 0) {
        return JO_INCORRECT_KEY_TYPE;
    }

    const size_t min_len = (size_t) slh_n * 2;

    switch (typeId) {
        case KS_SLH_DSA_SHA2_128f:
            type = "SLH-DSA-SHA2-128F";
            break;
        case KS_SLH_DSA_SHA2_128s:
            type = "SLH-DSA-SHA2-128S";
            break;
        case KS_SLH_DSA_SHAKE_128f:
            type = "SLH-DSA-SHAKE-128F";
            break;
        case KS_SLH_DSA_SHAKE_128s:
            type = "SLH-DSA-SHAKE-128S";
            break;
        case KS_SLH_DSA_SHA2_192f:
            type = "SLH-DSA-SHA2-192F";
            break;
        case KS_SLH_DSA_SHA2_192s:
            type = "SLH-DSA-SHA2-192S";
            break;
        case KS_SLH_DSA_SHAKE_192s:
            type = "SLH-DSA-SHAKE-192S";
            break;
        case KS_SLH_DSA_SHAKE_192f:
            type = "SLH-DSA-SHAKE-192F";
            break;
        case KS_SLH_DSA_SHA2_256f:
            type = "SLH-DSA-SHA2-256F";
            break;
        case KS_SLH_DSA_SHA2_256s:
            type = "SLH-DSA-SHA2-256S";
            break;
        case KS_SLH_DSA_SHAKE_256f:
            type = "SLH-DSA-SHAKE-256F";
            break;
        case KS_SLH_DSA_SHAKE_256s:
            type = "SLH-DSA-SHAKE-256S";
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

    // Defensive: caller is expected to pass a fresh spec, but if the spec
    // already holds a key, dropping it on the floor would leak the EVP_PKEY.
    if (key_spec->key != NULL) {
        EVP_PKEY_free(key_spec->key);
        key_spec->key = NULL;
    }

    key_spec->key = EVP_PKEY_new_raw_public_key_ex(get_global_jostle_ossl_lib_ctx(), type,NULL, src, src_len);

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


slh_dsa_ctx *slh_dsa_ctx_create(int32_t *err) {
    slh_dsa_ctx *ctx = (slh_dsa_ctx *) OPENSSL_zalloc(sizeof(slh_dsa_ctx));
    jo_assert(ctx != NULL);
    *err = JO_SUCCESS;
    return ctx;
}


void slh_dsa_ctx_destroy(slh_dsa_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->sig != NULL) {
        EVP_SIGNATURE_free(ctx->sig);
    }

    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
    }


    if (ctx->msg_buf != NULL) {
        BIO_free_all(ctx->msg_buf);
    }

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

int32_t slh_dsa_ctx_init_sign(slh_dsa_ctx *ctx, const key_spec *key_spec, const uint8_t *sign_ctx, int32_t sign_ctx_len,
                              int32_t msg_encoding, int32_t deterministic, void *rand_src) {
    jo_assert(ctx != NULL);
    jo_assert(key_spec != NULL);

    if (rand_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    rand_set_java_srand_call(rand_src);

    int32_t ret_code = JO_FAIL;

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    if (sign_ctx_len >= MAX_CTX_LEN) {
        ret_code = JO_CONTEXT_BYTES_TOO_LONG;
        goto exit;
    }

    // No EVP / OSSL calls have run yet, so the queue clear belongs after the
    // soft-error checks above (which preserve prior state) and before any of
    // the resource-allocating work below.
    ERR_clear_error();

    OPENSSL_cleanse((void *) ctx->context, MAX_CTX_LEN);


    // sign_ctx_len < 0 is a valid sentinel ("no context bytes"); skip the
    // memcpy so we don't reinterpret a negative length as size_t.
    if (sign_ctx != NULL && sign_ctx_len > 0) {
        memcpy(ctx->context, sign_ctx, sign_ctx_len);
    }
    ctx->context_len = sign_ctx_len;

    if (ctx->sig != NULL) {
        EVP_SIGNATURE_free(ctx->sig);
        ctx->sig = NULL;
    }

    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
        ctx->pctx = NULL;
    }


    if (ctx->msg_buf != NULL) {
        BIO_free_all(ctx->msg_buf);
        ctx->msg_buf = NULL;
    }

    ctx->opp = SLH_DSA_SIGN;
    ctx->hash_mode = SLH_DSA_HASH_NONE;
    ctx->msg_encoding = msg_encoding;
    ctx->deterministic = deterministic;


    switch (ctx->msg_encoding) {
        case SLH_DSA_ME_NONE:
        case SLH_DSA_ME_PURE:
            break;
        default:
            ret_code = JO_INVALID_SLH_DSA_MSG_ENCODING_PARAM;
            goto exit;
    }

    switch (ctx->deterministic) {
        case SLH_DSA_DETERMINISTIC:
        case SLH_DSA_NON_DETERMINISTIC:
            break;
        default:
            ret_code = JO_INVALID_SLH_DSA_DETERMINISTIC_PARAM;
            goto exit;
    }


    const char *algo = EVP_PKEY_get0_type_name(key_spec->key);
    if (algo == NULL) {
        ret_code = JO_INCORRECT_KEY_TYPE;
        goto exit;
    }

    if (0 != strncmp(algo, "SLH-DSA", 7)) {
        ret_code = JO_INCORRECT_KEY_TYPE;
        goto exit;
    }

    ctx->sig = EVP_SIGNATURE_fetch(get_global_jostle_ossl_lib_ctx(), algo,NULL);

    // Short-circuit on fetch failure rather than letting NULL flow through to
    // sign_message_init and surface as a misleading downstream diagnostic.
    if (OPS_FAILED_CREATE_1 ctx->sig == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    // Clamp context_len for the OSSL_PARAM payload: negative is a "no context"
    // sentinel and must not be reinterpreted as size_t.
    const size_t param_ctx_len = ctx->context_len > 0 ? (size_t) ctx->context_len : 0;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx->context, param_ctx_len),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, (void *)&ctx->msg_encoding),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, (void *)&ctx->deterministic),
        OSSL_PARAM_END
    };


    ctx->pctx = EVP_PKEY_CTX_new_from_pkey(get_global_jostle_ossl_lib_ctx(), key_spec->key, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx->pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1000);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_sign_message_init(ctx->pctx, ctx->sig, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1001);
        goto exit;
    }

    ctx->msg_buf = BIO_new(BIO_s_mem());

    if (OPS_FAILED_CREATE_2 ctx->msg_buf == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1002);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    if (ret_code != JO_SUCCESS) {
        // Roll back any partial state on failure so a subsequent update/sign
        // call sees a "not initialized" context rather than a half-configured
        // one that would leak through and surface confusing OpenSSL errors.
        if (ctx->sig != NULL) {
            EVP_SIGNATURE_free(ctx->sig);
            ctx->sig = NULL;
        }
        if (ctx->pctx != NULL) {
            EVP_PKEY_CTX_free(ctx->pctx);
            ctx->pctx = NULL;
        }
        if (ctx->msg_buf != NULL) {
            BIO_free_all(ctx->msg_buf);
            ctx->msg_buf = NULL;
        }
    }
    return ret_code;
}

int32_t slh_dsa_ctx_init_verify(
    slh_dsa_ctx *ctx,
    const key_spec *key_spec,
    const uint8_t *sign_ctx,
    int32_t sign_ctx_len,
    int32_t msg_encoding,
    int32_t deterministic
) {
    jo_assert(ctx != NULL);
    jo_assert(key_spec != NULL);

    int32_t ret_code = JO_FAIL;

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    if (sign_ctx_len >= MAX_CTX_LEN) {
        ret_code = JO_CONTEXT_BYTES_TOO_LONG;
        goto exit;
    }

    // No EVP / OSSL calls have run yet, so the queue clear belongs after the
    // soft-error checks above (which preserve prior state) and before any of
    // the resource-allocating work below.
    ERR_clear_error();

    OPENSSL_cleanse((void *) ctx->context, MAX_CTX_LEN);

    // sign_ctx_len < 0 is a valid sentinel ("no context bytes"); skip the
    // memcpy so we don't reinterpret a negative length as size_t.
    if (sign_ctx != NULL && sign_ctx_len > 0) {
        memcpy(ctx->context, sign_ctx, sign_ctx_len);
    }

    ctx->context_len = sign_ctx_len;

    // Free last used signature and PKEY
    if (ctx->sig != NULL) {
        EVP_SIGNATURE_free(ctx->sig);
        ctx->sig = NULL;
    }

    if (ctx->pctx != NULL) {
        EVP_PKEY_CTX_free(ctx->pctx);
        ctx->pctx = NULL;
    }

    if (ctx->msg_buf != NULL) {
        BIO_free_all(ctx->msg_buf);
        ctx->msg_buf = NULL;
    }

    ctx->opp = SLH_DSA_VERIFY;
    ctx->msg_encoding = msg_encoding;
    ctx->deterministic = deterministic;

    switch (ctx->msg_encoding) {
        case SLH_DSA_ME_NONE:
        case SLH_DSA_ME_PURE:
            break;
        default:
            ret_code = JO_INVALID_SLH_DSA_MSG_ENCODING_PARAM;
            goto exit;
    }

    switch (ctx->deterministic) {
        case SLH_DSA_DETERMINISTIC:
        case SLH_DSA_NON_DETERMINISTIC:
            break;
        default:
            ret_code = JO_INVALID_SLH_DSA_DETERMINISTIC_PARAM;
            goto exit;
    }


    const char *algo = EVP_PKEY_get0_type_name(key_spec->key);
    if (algo == NULL) {
        ret_code = JO_INCORRECT_KEY_TYPE;
        goto exit;
    }

    if (0 != strncmp(algo, "SLH-DSA", 7)) {
        ret_code = JO_INCORRECT_KEY_TYPE;
        goto exit;
    }


    // Clamp context_len for the OSSL_PARAM payload: negative is a "no context"
    // sentinel and must not be reinterpreted as size_t.
    const size_t param_ctx_len = ctx->context_len > 0 ? (size_t) ctx->context_len : 0;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx->context, param_ctx_len),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, (void *)&ctx->msg_encoding),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, (void *)&ctx->deterministic),
        OSSL_PARAM_END
    };

    ctx->sig = EVP_SIGNATURE_fetch(get_global_jostle_ossl_lib_ctx(), algo,NULL);

    // Short-circuit on fetch failure rather than letting NULL flow through to
    // verify_message_init and surface as a misleading downstream diagnostic.
    if (OPS_FAILED_CREATE_1 ctx->sig == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ctx->pctx = EVP_PKEY_CTX_new_from_pkey(get_global_jostle_ossl_lib_ctx(), key_spec->key, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx->pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1003);
        goto exit;
    }


    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_verify_message_init(ctx->pctx, ctx->sig, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1004);
        goto exit;
    }


    ctx->msg_buf = BIO_new(BIO_s_mem());

    if (OPS_FAILED_CREATE_2 ctx->msg_buf == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1005);
        goto exit;
    }
    ret_code = JO_SUCCESS;


exit:
    if (ret_code != JO_SUCCESS) {
        // Roll back any partial state on failure so a subsequent verify call
        // sees a "not initialized" context rather than a half-configured one
        // that would leak through and surface confusing OpenSSL errors.
        if (ctx->sig != NULL) {
            EVP_SIGNATURE_free(ctx->sig);
            ctx->sig = NULL;
        }
        if (ctx->pctx != NULL) {
            EVP_PKEY_CTX_free(ctx->pctx);
            ctx->pctx = NULL;
        }
        if (ctx->msg_buf != NULL) {
            BIO_free_all(ctx->msg_buf);
            ctx->msg_buf = NULL;
        }
    }
    return ret_code;
}


int32_t slh_dsa_ctx_sign(const slh_dsa_ctx *ctx, const uint8_t *out, const size_t out_len, void *rand_src) {
    jo_assert(ctx != NULL);
    int ret_code = JO_FAIL;

    // Hoisted so the unified cleanse at exit always sees an initialised
    // pointer regardless of which goto-exit path fired.
    uint8_t *msg = NULL;
    size_t msg_len = 0;

    if (rand_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    rand_set_java_srand_call(rand_src);

    ERR_clear_error();

    if (ctx->msg_buf == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (ctx->opp != SLH_DSA_SIGN) {
        ret_code = JO_UNEXPECTED_STATE;
        goto exit;
    }

    size_t sig_len = 0;


    /* Java API can query for length by passing null array */

    if (OPS_OPENSSL_ERROR_1 1 != EVP_PKEY_sign(ctx->pctx, NULL, &sig_len,NULL, 0)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }


    if (OPS_INT32_OVERFLOW_1 sig_len > INT32_MAX) {
        ret_code = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }


    if (out != NULL) {
        if (sig_len > out_len) {
            ret_code = JO_OUTPUT_TOO_SMALL;
            goto exit;
        }

        const size_t sig_len_ = sig_len;

        msg_len = BIO_get_mem_data(ctx->msg_buf, &msg);


        if (OPS_OPENSSL_ERROR_2 (1 != EVP_PKEY_sign(ctx->pctx, (unsigned char *) out, &sig_len, msg, msg_len))) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;;
        }

        if (OPS_LEN_CHANGE_1 sig_len_ != sig_len) {
            ret_code = JO_UNEXPECTED_SIG_LEN_CHANGE;
            goto exit;
        }
    }

    /* integer overflow tested by this point */
    ret_code = (int32_t) sig_len;


exit:
    // Cleanse the buffered message regardless of how we exit — protects
    // sensitive plaintext if EVP_PKEY_sign or the length-check fails.
    if (msg != NULL && msg_len > 0) {
        OPENSSL_cleanse(msg, msg_len);
    }
    return ret_code;
}

int32_t slh_dsa_ctx_verify(const slh_dsa_ctx *ctx, const uint8_t *sig, const size_t sig_len) {
    jo_assert(ctx != NULL);
    int ret_code = JO_FAIL;

    if (ctx->msg_buf == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (ctx->opp != SLH_DSA_VERIFY) {
        ret_code = JO_UNEXPECTED_STATE;
        goto exit;
    }

    uint8_t *msg = NULL;
    const size_t msg_len = BIO_get_mem_data(ctx->msg_buf, &msg);

    // Clear any stale errors from the thread's queue before marking, so the
    // mark sits at an empty state and ERR_pop_to_mark on a verify-false path
    // can't surface unrelated prior errors.
    ERR_clear_error();
    ERR_set_mark();
    int ret = EVP_PKEY_verify(ctx->pctx, sig, sig_len, msg, msg_len);
    OPENSSL_cleanse(msg, msg_len);

    if (OPS_OPENSSL_ERROR_1 0) {
        ERR_pop_to_mark();
        ret = -1;
    }

    if (ret == 1) {
        ERR_clear_last_mark();
        ret_code = JO_SUCCESS;
    } else {
        if (ret < 0) {
            // Real OpenSSL error — keep the queued errors for diagnosis,
            // but drop the mark so it doesn't accumulate across calls.
            ERR_clear_last_mark();
            ret_code = JO_OPENSSL_ERROR;
        } else {
            // Plain verification failure — discard any noise EVP_PKEY_verify
            // pushed onto the queue.
            ERR_pop_to_mark();
            ret_code = JO_FAIL;
        }
    }

exit:
    return ret_code;
}


int32_t slh_dsa_update(const slh_dsa_ctx *ctx, const uint8_t *in, const size_t in_len) {
    jo_assert(ctx != NULL);
    jo_assert(in != NULL);
    int32_t ret_code = JO_FAIL;

    if (ctx->msg_buf == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (in_len > INT32_MAX) {
        ret_code = JO_INPUT_TOO_LONG_INT32;
        goto exit;
    }

    ERR_clear_error();

    // BIO_write returns the number of bytes written, so a zero-length request
    // returns 0 — which the truthy check below would mistake for an error.
    // Skip the call entirely; an empty update is a no-op.
    if (in_len > 0) {
        if (OPS_OPENSSL_ERROR_1 !BIO_write(ctx->msg_buf, in, (int) in_len)) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;
        }
    }

    ret_code = JO_SUCCESS;


exit:
    return ret_code;
}

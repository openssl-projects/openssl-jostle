//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "slhdsa.h"

#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "bc_err_codes.h"
#include "key_spec.h"
#include "ops.h"

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


int32_t slh_dsa_generate_key_pair(key_spec *spec, int32_t type, uint8_t *seed, size_t seed_len) {
    assert(spec != NULL);


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
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHA2_128F,NULL);
            break;
        case KS_SLH_DSA_SHA2_128s:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHA2_128S,NULL);
            break;
        case KS_SLH_DSA_SHA2_192f:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHA2_192F,NULL);
            break;
        case KS_SLH_DSA_SHA2_192s:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHA2_192S,NULL);
            break;
        case KS_SLH_DSA_SHA2_256f:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHA2_256F,NULL);
            break;
        case KS_SLH_DSA_SHA2_256s:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHA2_256S,NULL);
            break;
        case KS_SLH_DSA_SHAKE_128f:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHAKE_128F,NULL);
            break;
        case KS_SLH_DSA_SHAKE_128s:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHAKE_128S,NULL);
            break;
        case KS_SLH_DSA_SHAKE_192f:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHAKE_192F,NULL);
            break;
        case KS_SLH_DSA_SHAKE_192s:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHAKE_192S,NULL);
            break;
        case KS_SLH_DSA_SHAKE_256f:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHAKE_256F,NULL);
            break;
        case KS_SLH_DSA_SHAKE_256s:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHAKE_256S,NULL);
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

    if (!EVP_PKEY_CTX_set_params(ctx, params)) {
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

int32_t slh_dsa_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }


    // const int slh_n = get_n(key_spec->type);
    // if (slh_n <= 0) {
    //     return JO_INCORRECT_KEY_TYPE;
    // }


    size_t min_len; // = (size_t) slh_n * 2;

    if (OPS_OPENSSL_ERROR_1 !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &min_len)) {
        return JO_OPENSSL_ERROR;
    }


    if (out == NULL) {
        return (int32_t) min_len;
    }


    if (out_len < min_len) {
        return JO_OUTPUT_TOO_SMALL;
    }

    size_t written = 0;

    if (OPS_OPENSSL_ERROR_2 !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out, min_len, &written)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t slh_dsa_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len) {
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }




    size_t min_len; // = (size_t) slh_n * 4;

    if (OPS_OPENSSL_ERROR_1 !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &min_len)) {
        return JO_OPENSSL_ERROR;
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

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t slh_dsa_get_private_seed(key_spec *key_spec, uint8_t *out, size_t out_len) {
    EVP_PKEY *pkey = key_spec->key;

    if (pkey == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    size_t min_len; // = slh_n * 3;

    if (OPS_OPENSSL_ERROR_1
        !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_SLH_DSA_SEED, NULL, 0, &min_len)) {
        return JO_OPENSSL_ERROR;
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

    if (OPS_INT32_OVERFLOW_1 written > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (int32_t) written;
}

int32_t slh_dsa_decode_private_key(key_spec *key_spec, int32_t typeId, uint8_t *src, size_t src_len) {
    int32_t ret_code = JO_FAIL;
    const char *type;

    assert(key_spec != NULL);

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


    key_spec->key = EVP_PKEY_new_raw_private_key_ex(NULL, type,NULL, src, src_len);

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

    assert(key_spec != NULL);

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


    key_spec->key = EVP_PKEY_new_raw_public_key_ex(NULL, type,NULL, src, src_len);

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


slh_dsa_ctx *slh_dsa_ctx_create(void) {
    slh_dsa_ctx *ctx = (slh_dsa_ctx *) OPENSSL_zalloc(sizeof(slh_dsa_ctx));
    assert(ctx);
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
                              int32_t msg_encoding, int32_t deterministic) {
    assert(ctx != NULL);
    assert(key_spec != NULL);

    int32_t ret_code = JO_FAIL;

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    if (sign_ctx_len >= MAX_CTX_LEN) {
        ret_code = JO_CONTEXT_BYTES_TOO_LONG;
        goto exit;
    }

    OPENSSL_cleanse((void *) ctx->context, MAX_CTX_LEN);


    if (sign_ctx != NULL) {
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


    // switch (key_spec->type) {
    //     case KS_SLH_DSA_SHA2_128f:
    //         algo = "SLH-DSA-SHA2-128F";
    //         break;
    //     case KS_SLH_DSA_SHA2_128s:
    //         algo = "SLH-DSA-SHA2-128S";
    //         break;
    //     case KS_SLH_DSA_SHAKE_128f:
    //         algo = "SLH-DSA-SHAKE-128F";
    //         break;
    //     case KS_SLH_DSA_SHAKE_128s:
    //         algo = "SLH-DSA-SHAKE-128S";
    //         break;
    //     case KS_SLH_DSA_SHA2_192f:
    //         algo = "SLH-DSA-SHA2-192F";
    //         break;
    //     case KS_SLH_DSA_SHA2_192s:
    //         algo = "SLH-DSA-SHA2-192S";
    //         break;
    //     case KS_SLH_DSA_SHAKE_192s:
    //         algo = "SLH-DSA-SHAKE-192S";
    //         break;
    //     case KS_SLH_DSA_SHAKE_192f:
    //         algo = "SLH-DSA-SHAKE-192F";
    //         break;
    //     case KS_SLH_DSA_SHA2_256f:
    //         algo = "SLH-DSA-SHA2-256F";
    //         break;
    //     case KS_SLH_DSA_SHA2_256s:
    //         algo = "SLH-DSA-SHA2-256S";
    //         break;
    //     case KS_SLH_DSA_SHAKE_256f:
    //         algo = "SLH-DSA-SHAKE-256F";
    //         break;
    //     case KS_SLH_DSA_SHAKE_256s:
    //         algo = "SLH-DSA-SHAKE-256S";
    //         break;
    //     default:
    //         ret_code = JO_INCORRECT_KEY_TYPE;
    //         goto exit;
    // }


    ctx->sig = EVP_SIGNATURE_fetch(NULL, algo,NULL);

    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx->context, ctx->context_len),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, (void *)&ctx->msg_encoding),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, (void *)&ctx->deterministic),
        OSSL_PARAM_END
    };


    ctx->pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key_spec->key, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx->pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1000);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_sign_message_init(ctx->pctx, ctx->sig, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1001);
        goto exit;
    }

    ctx->msg_buf = BIO_new(BIO_s_mem());

    if (ctx->msg_buf == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1002);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
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
    assert(ctx != NULL);
    assert(key_spec != NULL);

    int32_t ret_code = JO_FAIL;

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    if (sign_ctx_len >= MAX_CTX_LEN) {
        ret_code = JO_CONTEXT_BYTES_TOO_LONG;
        goto exit;
    }

    OPENSSL_cleanse((void *) ctx->context, MAX_CTX_LEN);

    if (sign_ctx != NULL) {
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


    // switch (key_spec->type) {
    //     case KS_SLH_DSA_SHA2_128f:
    //         algo = "SLH-DSA-SHA2-128F";
    //         break;
    //     case KS_SLH_DSA_SHA2_128s:
    //         algo = "SLH-DSA-SHA2-128S";
    //         break;
    //     case KS_SLH_DSA_SHAKE_128f:
    //         algo = "SLH-DSA-SHAKE-128F";
    //         break;
    //     case KS_SLH_DSA_SHAKE_128s:
    //         algo = "SLH-DSA-SHAKE-128S";
    //         break;
    //     case KS_SLH_DSA_SHA2_192f:
    //         algo = "SLH-DSA-SHA2-192F";
    //         break;
    //     case KS_SLH_DSA_SHA2_192s:
    //         algo = "SLH-DSA-SHA2-192S";
    //         break;
    //     case KS_SLH_DSA_SHAKE_192s:
    //         algo = "SLH-DSA-SHAKE-192S";
    //         break;
    //     case KS_SLH_DSA_SHAKE_192f:
    //         algo = "SLH-DSA-SHAKE-192F";
    //         break;
    //     case KS_SLH_DSA_SHA2_256f:
    //         algo = "SLH-DSA-SHA2-256F";
    //         break;
    //     case KS_SLH_DSA_SHA2_256s:
    //         algo = "SLH-DSA-SHA2-256S";
    //         break;
    //     case KS_SLH_DSA_SHAKE_256f:
    //         algo = "SLH-DSA-SHAKE-256F";
    //         break;
    //     case KS_SLH_DSA_SHAKE_256s:
    //         algo = "SLH-DSA-SHAKE-256S";
    //         break;
    //     default:
    //         ret_code = JO_INCORRECT_KEY_TYPE;
    //         goto exit;
    // }

    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, ctx->context, ctx->context_len),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, (void *)&ctx->msg_encoding),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, (void *)&ctx->deterministic),
        OSSL_PARAM_END
    };

    ctx->sig = EVP_SIGNATURE_fetch(NULL, algo,NULL);
    ctx->pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key_spec->key, NULL);

    if (OPS_OPENSSL_ERROR_1 ctx->pctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1003);
        goto exit;
    }


    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_verify_message_init(ctx->pctx, ctx->sig, params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1004);
        goto exit;
    }


    ctx->msg_buf = BIO_new(BIO_s_mem());

    if (ctx->msg_buf == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1005);
        goto exit;
    }
    ret_code = JO_SUCCESS;


exit:

    return ret_code;
}


int32_t slh_dsa_ctx_sign(const slh_dsa_ctx *ctx, const uint8_t *out, const size_t out_len) {
    assert(ctx != NULL);
    int ret_code = JO_FAIL;

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

        uint8_t *msg;
        const size_t msg_len = BIO_get_mem_data(ctx->msg_buf, &msg);


        if (OPS_OPENSSL_ERROR_2 (1 != EVP_PKEY_sign(ctx->pctx, (unsigned char *) out, &sig_len, msg, msg_len))) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;;
        }

        OPENSSL_cleanse(msg, msg_len);

        if (OPS_LEN_CHANGE_1 sig_len_ != sig_len) {
            ret_code = JO_UNEXPECTED_SIG_LEN_CHANGE;
            goto exit;
        }
    }

    /* integer overflow tested by this point */
    ret_code = (int32_t) sig_len;


exit:
    return ret_code;
}

int32_t slh_dsa_ctx_verify(const slh_dsa_ctx *ctx, const uint8_t *sig, const size_t sig_len) {
    assert(ctx != NULL);
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
            ret_code = JO_OPENSSL_ERROR;
        } else {
            ERR_pop_to_mark();
            ret_code = JO_FAIL;
        }
    }

exit:
    return ret_code;
}


int32_t slh_dsa_update(const slh_dsa_ctx *ctx, const uint8_t *in, const size_t in_len) {
    assert(ctx != NULL);
    int32_t ret_code = JO_FAIL;

    if (ctx->msg_buf == NULL) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }


    if (OPS_OPENSSL_ERROR_1 !BIO_write(ctx->msg_buf, in, (int) in_len)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;


exit:
    return ret_code;
}

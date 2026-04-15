//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#include "edec.h"

#include <_string.h>
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
    return ret_code;
}


edec_ctx *edec_ctx_create(int32_t *err) {
    jo_assert(err != NULL);

    edec_ctx *ctx = (edec_ctx *) OPENSSL_zalloc(sizeof(edec_ctx));
    jo_assert(ctx != NULL);

    ctx->message = BIO_new(BIO_s_mem());
    if (OPS_OPENSSL_ERROR_1 ctx->message == NULL) {
        *err = JO_OPENSSL_ERROR;
        OPENSSL_clear_free(ctx, sizeof(*ctx));
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
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1000);
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


    if (OPS_OPENSSL_ERROR_2 1 != EVP_DigestSignInit_ex(ctx->digest_ctx, NULL, NULL, libctx, NULL, key_spec->key,
                                                       params)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1001);
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
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1003);
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
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET(1004);
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


    if (BIO_write(ctx->message, in, (int) in_len) < 0) {
        return JO_OPENSSL_ERROR;
    }

    return JO_SUCCESS;
}


int32_t edec_ctx_sign(const edec_ctx *ctx, const uint8_t *out, const size_t out_len, void *rnd_src) {
    jo_assert(ctx != NULL);
    int ret_code = JO_FAIL;

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
    const size_t msg_len = BIO_get_mem_data(ctx->message, &msg);

    size_t sig_len = 0;
    rand_set_java_srand_call(rnd_src);
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
            ret_code = JO_OUTPUT_TOO_SMALL;
            goto exit;
        }


        const size_t sig_len_ = sig_len;

        rand_set_java_srand_call(rnd_src);
        int code = EVP_DigestSign(ctx->digest_ctx, (unsigned char *) out, &sig_len, msg, msg_len);
        if (OPS_OPENSSL_ERROR_2 1 != code) {
            ret_code = JO_OPENSSL_ERROR;
            goto exit;
        }


        if (OPS_LEN_CHANGE_1 sig_len_ != sig_len) {
            ret_code = JO_UNEXPECTED_SIG_LEN_CHANGE;
            goto exit;
        }

        BIO_reset(ctx->message);
    }

    ret_code = (int32_t) sig_len;

exit:
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


    // OpenSSL may emit an error message about an invalid signature which we don't care about.
    ERR_set_mark();

    uint8_t *msg = NULL;
    const size_t msg_len = BIO_get_mem_data(ctx->message, &msg);
    int ret = EVP_DigestVerify(ctx->digest_ctx, (unsigned char *) sig, sig_len, msg, msg_len);
    ERR_pop_to_mark();
    BIO_reset(ctx->message);

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

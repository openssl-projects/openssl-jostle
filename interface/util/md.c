//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "md.h"


#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "bc_err_codes.h"
#include "ops.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"

md_ctx *md_ctx_create(const char *name, int xof_len, int *err) {
    ERR_clear_error();

    EVP_MD *md = EVP_MD_fetch(get_global_jostle_ossl_lib_ctx(), name,NULL);
    if (md == NULL) {
        *err = JO_NAME_NOT_FOUND;
        return NULL;
    }

    // Reject mismatched xof_len up front so the NI surface can't enter a
    // broken state where xof=0 but the algorithm is XOF (or vice versa).
    const int is_xof = EVP_MD_xof(md);
    if ((is_xof && xof_len <= 0) || (!is_xof && xof_len > 0)) {
        EVP_MD_free(md);
        *err = JO_MD_XOF_LEN_INVALID;
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (OPS_FAILED_CREATE_1 mdctx == NULL) {
        EVP_MD_free(md);
        *err = JO_MD_CREATE_FAILED;
        return NULL;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_DIGEST_PARAM_XOFLEN, &xof_len),
        OSSL_PARAM_END
    };
    const OSSL_PARAM *params_ptr = is_xof ? params : NULL;

    if (OPS_FAILED_INIT_1 !EVP_DigestInit_ex2(mdctx, md, params_ptr)) {
        EVP_MD_CTX_free(mdctx);
        EVP_MD_free(md);
        *err = JO_MD_INIT_FAILED;
        return NULL;
    }


    int fixed_size = 0;
    if (!is_xof) {
        fixed_size = EVP_MD_get_size(md);
        // Non-XOF digest with no fixed size (or negative) — should not happen
        // for any digest registered via ProvMD, but bail out cleanly so the
        // ctx never carries digest_byte_length <= 0.
        if (fixed_size <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_MD_free(md);
            *err = JO_MD_INIT_FAILED;
            return NULL;
        }
    }

    md_ctx *ctx = OPENSSL_zalloc(sizeof(md_ctx));
    jo_assert(ctx != NULL);
    ctx->md_type = md;
    ctx->mdctx = mdctx;

    if (is_xof) {
        ctx->digest_byte_length = xof_len;
        ctx->xof = 1;
    } else {
        ctx->digest_byte_length = fixed_size;
        ctx->xof = 0;
    }


    *err = JO_SUCCESS;
    return ctx;
}

void md_ctx_destroy(md_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->mdctx != NULL) {
        EVP_MD_CTX_free(ctx->mdctx);
    }
    if (ctx->md_type != NULL) {
        EVP_MD_free((EVP_MD *) ctx->md_type);
    }
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

//     CRYPTO_THREAD_LOCAL local = CRYPTO_THREAD_get_current_id()

int32_t md_ctx_update(md_ctx *ctx, uint8_t *data, size_t len) {
    jo_assert(ctx != NULL);
    jo_assert(ctx->mdctx != NULL);

    // Bridges constrain `len` to int32, but md_ctx_update is exported. Guard
    // the narrowing return cast for direct C callers.
    if (len > INT_MAX) {
        return JO_MD_DIGEST_LEN_INT_OVERFLOW;
    }

    ERR_clear_error();
    if (OPS_OPENSSL_ERROR_1 !EVP_DigestUpdate(ctx->mdctx, data, len)) {
        return JO_OPENSSL_ERROR;
    }
    return (int32_t) len;
}

int32_t md_ctx_finalize(md_ctx *ctx, uint8_t *digest) {
    jo_assert(ctx != NULL);
    jo_assert(ctx->mdctx != NULL);
    ERR_clear_error();

    uint32_t ret_len = 0;

    if (ctx->xof != 0) {
        if (OPS_OPENSSL_ERROR_1 !EVP_DigestFinalXOF(ctx->mdctx, digest, ctx->digest_byte_length)) {
            return JO_OPENSSL_ERROR;
        }
        ret_len = ctx->digest_byte_length;
    } else {
        if (OPS_OPENSSL_ERROR_2 !EVP_DigestFinal_ex(ctx->mdctx, digest, &ret_len)) {
            return JO_OPENSSL_ERROR;
        }
    }

    if (OPS_INT32_OVERFLOW_1 ret_len > INT_MAX) {
        return JO_MD_DIGEST_LEN_INT_OVERFLOW;
    }

    return (int32_t) ret_len;
}

int32_t md_ctx_reset(md_ctx *ctx) {
    jo_assert(ctx != NULL);
    jo_assert(ctx->mdctx != NULL);
    ERR_clear_error();

    int xof_len = ctx->digest_byte_length;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_DIGEST_PARAM_XOFLEN, &xof_len),
        OSSL_PARAM_END
    };
    const OSSL_PARAM *params_ptr = ctx->xof ? params : NULL;

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md_type, params_ptr)) {
        return JO_OPENSSL_ERROR;
    }


    return JO_SUCCESS;
}

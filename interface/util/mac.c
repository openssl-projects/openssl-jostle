//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "mac.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include <string.h>
#include <strings.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"

struct jo_mac_ctx_st
{
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    char *mac_name;
    char *digest_name;
    uint8_t *key;
    size_t key_len;
    int mac_len;
    int initialized;
};

static int ci_eq(const char *a, const char *b)
{
    return strcasecmp(a, b) == 0;
}

static const char *normalize_name(const char *name)
{
    if (name == NULL)
    {
        return NULL;
    }
    if (ci_eq(name, "SHA2-256") || ci_eq(name, "SHA-256") || ci_eq(name, "SHA256"))
    {
        return "SHA256";
    }
    if (ci_eq(name, "SHA2-384") || ci_eq(name, "SHA-384") || ci_eq(name, "SHA384"))
    {
        return "SHA384";
    }
    if (ci_eq(name, "SHA2-512") || ci_eq(name, "SHA-512") || ci_eq(name, "SHA512"))
    {
        return "SHA512";
    }
    if (ci_eq(name, "SHA2-224") || ci_eq(name, "SHA-224") || ci_eq(name, "SHA224"))
    {
        return "SHA224";
    }
    if (ci_eq(name, "SHA1") || ci_eq(name, "SHA-1"))
    {
        return "SHA1";
    }
    return name;
}

static int32_t init_mac_ctx(jo_mac_ctx *mctx)
{
    OSSL_PARAM params[2];

    if (mctx == NULL || mctx->ctx == NULL || mctx->key == NULL)
    {
        return JO_NOT_INITIALIZED;
    }

    if (mctx->digest_name != NULL)
    {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, mctx->digest_name, 0);
        params[1] = OSSL_PARAM_construct_end();
    }
    else
    {
        params[0] = OSSL_PARAM_construct_end();
    }

    if (OPS_OPENSSL_ERROR_2 EVP_MAC_init(mctx->ctx, mctx->key, mctx->key_len, params) != 1)
    {
        return JO_OPENSSL_ERROR;
    }

    mctx->initialized = 1;
    return JO_SUCCESS;
}

int32_t jo_mac_new(const char *mac_name, const char *canonical_name, uintptr_t *out_ctx)
{
    jo_mac_ctx *mctx = NULL;
    size_t mac_name_len;
    const char *norm_name;
    size_t name_len;

    if (out_ctx == NULL)
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    *out_ctx = (uintptr_t)0;

    if (mac_name == NULL || canonical_name == NULL)
    {
        return JO_NAME_IS_NULL;
    }

    norm_name = normalize_name(canonical_name);
    if (mac_name[0] == '\0' || norm_name == NULL || norm_name[0] == '\0')
    {
        return JO_NAME_NOT_FOUND;
    }

    mctx = OPENSSL_zalloc(sizeof(*mctx));
    if (mctx == NULL)
    {
        return JO_FAIL;
    }

    mac_name_len = strlen(mac_name) + 1;
    mctx->mac_name = OPENSSL_malloc(mac_name_len);
    if (mctx->mac_name == NULL)
    {
        OPENSSL_free(mctx);
        return JO_FAIL;
    }
    memcpy(mctx->mac_name, mac_name, mac_name_len);

    name_len = strlen(norm_name) + 1;
    mctx->digest_name = OPENSSL_malloc(name_len);
    if (mctx->digest_name == NULL)
    {
        OPENSSL_free(mctx->mac_name);
        OPENSSL_free(mctx);
        return JO_FAIL;
    }
    memcpy(mctx->digest_name, norm_name, name_len);

    mctx->mac = EVP_MAC_fetch(NULL, mctx->mac_name, NULL);
    if (OPS_OPENSSL_ERROR_1 mctx->mac == NULL)
    {
        OPENSSL_free(mctx->mac_name);
        OPENSSL_free(mctx->digest_name);
        OPENSSL_free(mctx);
        return JO_OPENSSL_ERROR;
    }

    mctx->ctx = EVP_MAC_CTX_new(mctx->mac);
    if (mctx->ctx == NULL)
    {
        EVP_MAC_free(mctx->mac);
        OPENSSL_free(mctx->mac_name);
        OPENSSL_free(mctx->digest_name);
        OPENSSL_free(mctx);
        return JO_OPENSSL_ERROR;
    }

    *out_ctx = (uintptr_t)mctx;
    return JO_SUCCESS;
}

int32_t jo_mac_init(uintptr_t ctx, const uint8_t *key, size_t key_len)
{
    jo_mac_ctx *mctx;
    uint8_t *new_key;
    int32_t ret;

    if (ctx == 0)
    {
        return JO_NOT_INITIALIZED;
    }
    if (key == NULL)
    {
        return JO_KEY_IS_NULL;
    }

    mctx = (jo_mac_ctx *)ctx;

    new_key = OPENSSL_malloc(key_len == 0 ? 1 : key_len);
    if (new_key == NULL)
    {
        return JO_FAIL;
    }

    if (key_len > 0)
    {
        memcpy(new_key, key, key_len);
    }

    if (mctx->key != NULL)
    {
        OPENSSL_clear_free(mctx->key, mctx->key_len);
    }

    mctx->key = new_key;
    mctx->key_len = key_len;

    ret = init_mac_ctx(mctx);
    if (ret < 0)
    {
        OPENSSL_clear_free(mctx->key, mctx->key_len);
        mctx->key = NULL;
        mctx->key_len = 0;
        mctx->initialized = 0;
        return ret;
    }

    return JO_SUCCESS;
}

int32_t jo_mac_update(uintptr_t ctx, const uint8_t *in, int32_t off, int32_t len)
{
    jo_mac_ctx *mctx;

    if (ctx == 0)
    {
        return JO_NOT_INITIALIZED;
    }
    if (in == NULL)
    {
        return JO_INPUT_IS_NULL;
    }
    if (off < 0)
    {
        return JO_INPUT_OFFSET_IS_NEGATIVE;
    }
    if (len < 0)
    {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    if (len == 0)
    {
        return JO_SUCCESS;
    }

    mctx = (jo_mac_ctx *)ctx;
    if (!mctx->initialized)
    {
        return JO_NOT_INITIALIZED;
    }

    if (OPS_OPENSSL_ERROR_3 EVP_MAC_update(mctx->ctx, in + off, (size_t)len) != 1)
    {
        return JO_OPENSSL_ERROR;
    }

    return JO_SUCCESS;
}

int32_t jo_mac_final(uintptr_t ctx, uint8_t *out, int32_t off, int32_t out_len)
{
    jo_mac_ctx *mctx;
    size_t written = 0;

    if (ctx == 0)
    {
        return JO_NOT_INITIALIZED;
    }
    if (out == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    if (off < 0)
    {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }

    mctx = (jo_mac_ctx *)ctx;
    if (!mctx->initialized)
    {
        return JO_NOT_INITIALIZED;
    }

    if (mctx->mac_len <= 0)
    {
        mctx->mac_len = (int)EVP_MAC_CTX_get_mac_size(mctx->ctx);
    }
    if (mctx->mac_len <= 0)
    {
        return JO_OPENSSL_ERROR;
    }
    if (out_len < mctx->mac_len)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    if ((int64_t)off + (int64_t)mctx->mac_len > (int64_t)out_len)
    {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    if (OPS_OPENSSL_ERROR_1 EVP_MAC_final(mctx->ctx, out + off, &written, (size_t)(out_len - off)) != 1)
    {
        return JO_OPENSSL_ERROR;
    }

    return (int32_t)written;
}

int32_t jo_mac_len(uintptr_t ctx)
{
    jo_mac_ctx *mctx;

    if (ctx == 0)
    {
        return JO_NOT_INITIALIZED;
    }

    mctx = (jo_mac_ctx *)ctx;
    if (mctx->mac_len <= 0)
    {
        mctx->mac_len = (int)EVP_MAC_CTX_get_mac_size(mctx->ctx);
    }
    if (mctx->mac_len <= 0)
    {
        return JO_OPENSSL_ERROR;
    }

    return mctx->mac_len;
}

void jo_mac_reset(uintptr_t ctx)
{
    jo_mac_ctx *mctx;
    int32_t ret;

    if (ctx == 0)
    {
        return;
    }

    mctx = (jo_mac_ctx *)ctx;
    if (mctx->key == NULL)
    {
        return;
    }

    ret = init_mac_ctx(mctx);
    if (ret < 0)
    {
        mctx->initialized = 0;
    }
}

void jo_mac_free(uintptr_t ctx)
{
    jo_mac_ctx *mctx;

    if (ctx == 0)
    {
        return;
    }

    mctx = (jo_mac_ctx *)ctx;
    if (mctx->ctx != NULL)
    {
        EVP_MAC_CTX_free(mctx->ctx);
    }
    if (mctx->mac != NULL)
    {
        EVP_MAC_free(mctx->mac);
    }
    if (mctx->digest_name != NULL)
    {
        OPENSSL_free(mctx->digest_name);
    }
    if (mctx->mac_name != NULL)
    {
        OPENSSL_free(mctx->mac_name);
    }
    if (mctx->key != NULL)
    {
        OPENSSL_clear_free(mctx->key, mctx->key_len);
    }
    OPENSSL_free(mctx);
}

int32_t jo_mac_copy(uintptr_t ctx, uintptr_t *out_ctx)
{
    jo_mac_ctx *src;
    jo_mac_ctx *dst;
    size_t name_len;

    if (out_ctx == NULL)
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    *out_ctx = (uintptr_t)0;

    if (ctx == 0)
    {
        return JO_NOT_INITIALIZED;
    }

    src = (jo_mac_ctx *)ctx;
    if (!src->initialized)
    {
        return JO_NOT_INITIALIZED;
    }

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
    {
        return JO_FAIL;
    }

    name_len = strlen(src->mac_name) + 1;
    dst->mac_name = OPENSSL_malloc(name_len);
    if (dst->mac_name == NULL)
    {
        OPENSSL_free(dst);
        return JO_FAIL;
    }
    memcpy(dst->mac_name, src->mac_name, name_len);

    name_len = strlen(src->digest_name) + 1;
    dst->digest_name = OPENSSL_malloc(name_len);
    if (dst->digest_name == NULL)
    {
        OPENSSL_free(dst->mac_name);
        OPENSSL_free(dst);
        return JO_FAIL;
    }
    memcpy(dst->digest_name, src->digest_name, name_len);

    dst->mac = EVP_MAC_fetch(NULL, dst->mac_name, NULL);
    if (dst->mac == NULL)
    {
        OPENSSL_free(dst->mac_name);
        OPENSSL_free(dst->digest_name);
        OPENSSL_free(dst);
        return JO_NAME_NOT_FOUND;
    }

    dst->ctx = EVP_MAC_CTX_dup(src->ctx);
    if (dst->ctx == NULL)
    {
        EVP_MAC_free(dst->mac);
        OPENSSL_free(dst->mac_name);
        OPENSSL_free(dst->digest_name);
        OPENSSL_free(dst);
        return JO_OPENSSL_ERROR;
    }

    if (src->key != NULL)
    {
        dst->key = OPENSSL_malloc(src->key_len == 0 ? 1 : src->key_len);
        if (dst->key == NULL)
        {
            jo_mac_free((uintptr_t)dst);
            return JO_FAIL;
        }
        if (src->key_len > 0)
        {
            memcpy(dst->key, src->key, src->key_len);
        }
        dst->key_len = src->key_len;
    }

    dst->mac_len = src->mac_len;
    dst->initialized = src->initialized;

    *out_ctx = (uintptr_t)dst;
    return JO_SUCCESS;
}

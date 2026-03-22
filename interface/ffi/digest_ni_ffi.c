// Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
// Licensed under Apache 2.0
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <pthread.h>
#include "../util/bc_err_codes.h"
#include "digest_ni_ffi.h"

typedef struct jo_md_ctx_st
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;   // fetched digest (OpenSSL 3) or legacy pointer
    int md_size;        // cached size in bytes
} jo_md_ctx;

// Global default property query and FIPS toggle applied to default libctx.
static char *g_props = NULL; // e.g. fips=yes or provider=default
static pthread_mutex_t g_props_lock = PTHREAD_MUTEX_INITIALIZER;

static int translate_len(int32_t len)
{
    if (len < 0)
    {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }
    return JO_SUCCESS;
}

static int ci_eq(const char *a, const char *b)
{
    // case-insensitive compare for ASCII algorithm names
    // strcasecmp is POSIX; acceptable for our supported targets
    return strcasecmp(a, b) == 0;
}

static const char *normalize_name(const char *name)
{
    if (name == NULL)
    {
        return NULL;
    }
    // Map JCA canonical names to OpenSSL EVP names
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
    return name; // fallback: assume already OpenSSL-compatible
}

int32_t jo_digest_new(const char *canonical_name, uintptr_t *out_ctx)
{
    if (out_ctx == NULL)
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    *out_ctx = (uintptr_t)0;
    if (canonical_name == NULL)
    {
        return JO_PROV_NAME_NULL;
    }

    jo_md_ctx *mctx = (jo_md_ctx *)OPENSSL_zalloc(sizeof(jo_md_ctx));
    if (mctx == NULL)
    {
        return JO_FAIL;
    }

    mctx->ctx = EVP_MD_CTX_new();
    if (mctx->ctx == NULL)
    {
        OPENSSL_free(mctx);
        return JO_FAIL;
    }

    // Translate to an OpenSSL fetchable name
    const char *ossl_name = normalize_name(canonical_name);

    // Fetch digest by OpenSSL name using property query if set
    // Snapshot g_props under lock to avoid races with setter.
    char *props_local = NULL;
    pthread_mutex_lock(&g_props_lock);
    if (g_props != NULL)
    {
        size_t l = strlen(g_props) + 1;
        props_local = OPENSSL_malloc(l);
        if (props_local != NULL)
        {
            memcpy(props_local, g_props, l);
        }
    }
    pthread_mutex_unlock(&g_props_lock);

    mctx->md = EVP_MD_fetch(NULL, ossl_name, props_local);
    if (mctx->md == NULL)
    {
        // fallback: legacy lookup if available
        const EVP_MD *legacy = EVP_get_digestbyname(ossl_name);
        if (legacy != NULL)
        {
            mctx->md = legacy; // do not free legacy
        }
    }

    if (mctx->md == NULL)
    {
        // final fallback: direct getters to avoid provider issues
        if (strcmp(ossl_name, "SHA256") == 0)
        {
            mctx->md = EVP_sha256();
        }
        else if (strcmp(ossl_name, "SHA384") == 0)
        {
            mctx->md = EVP_sha384();
        }
        else if (strcmp(ossl_name, "SHA512") == 0)
        {
            mctx->md = EVP_sha512();
        }
    }

    if (mctx->md == NULL)
    {
        EVP_MD_CTX_free(mctx->ctx);
        OPENSSL_free(mctx);
        return JO_OPENSSL_ERROR;
    }

    if (EVP_DigestInit_ex(mctx->ctx, mctx->md, NULL) != 1)
    {
        EVP_MD_CTX_free(mctx->ctx);
        if (EVP_MD_get0_provider(mctx->md) != NULL) EVP_MD_free((EVP_MD *)mctx->md);
        OPENSSL_free(mctx);
        if (props_local) OPENSSL_free(props_local);
        return JO_OPENSSL_ERROR;
    }

    int size = EVP_MD_get_size(mctx->md);
    if (size <= 0)
    {
        EVP_MD_CTX_free(mctx->ctx);
        if (EVP_MD_get0_provider(mctx->md) != NULL) EVP_MD_free((EVP_MD *)mctx->md);
        OPENSSL_free(mctx);
        if (props_local) OPENSSL_free(props_local);
        return JO_OPENSSL_ERROR;
    }
    mctx->md_size = size;

    *out_ctx = (uintptr_t)mctx;
    if (props_local) OPENSSL_free(props_local);
    return JO_SUCCESS;
}

int32_t jo_digest_update(uintptr_t ctx, const uint8_t *in, int32_t off, int32_t len)
{
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
    int tr = translate_len(len);
    if (tr < 0)
    {
        return tr;
    }

    const jo_md_ctx *mctx = (const jo_md_ctx *)ctx;
    const uint8_t *src = in + off;
    if (len == 0)
    {
        return JO_SUCCESS;
    }
    if (EVP_DigestUpdate(mctx->ctx, src, (size_t)len) != 1)
    {
        return JO_OPENSSL_ERROR;
    }
    return JO_SUCCESS;
}

int32_t jo_digest_final(uintptr_t ctx, uint8_t *out, int32_t off, int32_t out_len)
{
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

    jo_md_ctx *mctx = (jo_md_ctx *)ctx;
    if (out_len < mctx->md_size)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    // guard against integer overflow and range errors: off >= 0 already checked above
    if ((int64_t)off + (int64_t)mctx->md_size > (int64_t)out_len)
    {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    unsigned int written = 0;
    if (EVP_DigestFinal_ex(mctx->ctx, out + off, &written) != 1)
    {
        return JO_OPENSSL_ERROR;
    }

    // Prepare for next use (JCA semantics: engineDigest resets the state)
    if (EVP_DigestInit_ex(mctx->ctx, mctx->md, NULL) != 1)
    {
        return JO_OPENSSL_ERROR;
    }

    return (int32_t)written;
}

int32_t jo_digest_len(uintptr_t ctx)
{
    if (ctx == 0)
    {
        return JO_NOT_INITIALIZED;
    }
    jo_md_ctx *mctx = (jo_md_ctx *)ctx;
    return mctx->md_size;
}

void jo_digest_reset(uintptr_t ctx)
{
    if (ctx == 0)
    {
        return;
    }
    jo_md_ctx *mctx = (jo_md_ctx *)ctx;
    (void)EVP_DigestInit_ex(mctx->ctx, mctx->md, NULL);
}

void jo_digest_free(uintptr_t ctx)
{
    if (ctx == 0)
    {
        return;
    }
    jo_md_ctx *mctx = (jo_md_ctx *)ctx;
    if (mctx->ctx != NULL)
    {
        EVP_MD_CTX_free(mctx->ctx);
    }
    if (mctx->md != NULL && EVP_MD_get0_provider(mctx->md) != NULL)
    {
        // Only free fetched digests; legacy digests are not owned
        EVP_MD_free((EVP_MD *)mctx->md);
    }
    OPENSSL_free(mctx);
}

int32_t jo_digest_copy(uintptr_t ctx, uintptr_t *out_ctx)
{
    if (out_ctx == NULL)
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    *out_ctx = (uintptr_t)0;
    if (ctx == 0)
    {
        return JO_NOT_INITIALIZED;
    }
    jo_md_ctx *src = (jo_md_ctx *)ctx;
    jo_md_ctx *dst = (jo_md_ctx *)OPENSSL_zalloc(sizeof(jo_md_ctx));
    if (dst == NULL)
    {
        return JO_FAIL;
    }
    dst->ctx = EVP_MD_CTX_new();
    if (dst->ctx == NULL)
    {
        OPENSSL_free(dst);
        return JO_FAIL;
    }
    // Share the same EVP_MD; up_ref if provider-backed, legacy is not owned
    dst->md = src->md;
    if (dst->md != NULL && EVP_MD_get0_provider(dst->md) != NULL)
    {
        if (EVP_MD_up_ref((EVP_MD *)dst->md) != 1)
        {
            EVP_MD_CTX_free(dst->ctx);
            OPENSSL_free(dst);
            return JO_OPENSSL_ERROR;
        }
    }
    if (EVP_MD_CTX_copy_ex(dst->ctx, src->ctx) != 1)
    {
        EVP_MD_CTX_free(dst->ctx);
        if (dst->md != NULL && EVP_MD_get0_provider(dst->md) != NULL)
        {
            EVP_MD_free((EVP_MD *)dst->md);
        }
        OPENSSL_free(dst);
        return JO_OPENSSL_ERROR;
    }
    dst->md_size = src->md_size;
    *out_ctx = (uintptr_t)dst;
    return JO_SUCCESS;
}

int32_t jo_digest_set_props(const char *props)
{
    pthread_mutex_lock(&g_props_lock);
    if (g_props != NULL)
    {
        OPENSSL_free(g_props);
        g_props = NULL;
    }
    if (props != NULL && props[0] != '\0')
    {
        size_t len = strlen(props) + 1;
        g_props = OPENSSL_malloc(len);
        if (g_props == NULL)
        {
            pthread_mutex_unlock(&g_props_lock);
            return JO_FAIL;
        }
        memcpy(g_props, props, len);
    }
    pthread_mutex_unlock(&g_props_lock);
    return JO_SUCCESS;
}

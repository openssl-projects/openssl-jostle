// Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
// Licensed under Apache 2.0
#include <jni.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <strings.h> // for strcasecmp
#include "../util/bc_err_codes.h"

typedef struct jo_md_ctx_st
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;   // fetched digest (OpenSSL 3) or legacy pointer
    int md_size;        // cached size in bytes
} jo_md_ctx;

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
    return name;
}

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_digest_DigestNIJNI_makeInstance
  (JNIEnv *env, jobject self, jstring canonicalAlgName)
{
    (void)self;
    if (canonicalAlgName == NULL)
    {
        return (jlong)0;
    }

    const char *jname = (*env)->GetStringUTFChars(env, canonicalAlgName, NULL);
    if (jname == NULL)
    {
        return (jlong)0;
    }

    const char *ossl_name = normalize_name(jname);

    jo_md_ctx *mctx = (jo_md_ctx *)OPENSSL_zalloc(sizeof(jo_md_ctx));
    if (mctx == NULL)
    {
        (*env)->ReleaseStringUTFChars(env, canonicalAlgName, jname);
        return (jlong)0;
    }

    mctx->ctx = EVP_MD_CTX_new();
    if (mctx->ctx == NULL)
    {
        OPENSSL_free(mctx);
        (*env)->ReleaseStringUTFChars(env, canonicalAlgName, jname);
        return (jlong)0;
    }

    // Try provider fetch, then legacy by name, then direct getters
    mctx->md = EVP_MD_fetch(NULL, ossl_name, NULL);
    if (mctx->md == NULL)
    {
        const EVP_MD *legacy = EVP_get_digestbyname(ossl_name);
        if (legacy != NULL)
        {
            mctx->md = legacy; // legacy not owned
        }
    }
    if (mctx->md == NULL)
    {
        if (strcmp(ossl_name, "SHA256") == 0) mctx->md = EVP_sha256();
        else if (strcmp(ossl_name, "SHA384") == 0) mctx->md = EVP_sha384();
        else if (strcmp(ossl_name, "SHA512") == 0) mctx->md = EVP_sha512();
    }
    if (mctx->md == NULL)
    {
        EVP_MD_CTX_free(mctx->ctx);
        OPENSSL_free(mctx);
        (*env)->ReleaseStringUTFChars(env, canonicalAlgName, jname);
        return (jlong)0;
    }

    if (EVP_DigestInit_ex(mctx->ctx, mctx->md, NULL) != 1)
    {
        EVP_MD_CTX_free(mctx->ctx);
        if (EVP_MD_get0_provider(mctx->md) != NULL) EVP_MD_free((EVP_MD *)mctx->md);
        OPENSSL_free(mctx);
        (*env)->ReleaseStringUTFChars(env, canonicalAlgName, jname);
        return (jlong)0;
    }

    int size = EVP_MD_get_size(mctx->md);
    if (size <= 0)
    {
        EVP_MD_CTX_free(mctx->ctx);
        if (EVP_MD_get0_provider(mctx->md) != NULL) EVP_MD_free((EVP_MD *)mctx->md);
        OPENSSL_free(mctx);
        (*env)->ReleaseStringUTFChars(env, canonicalAlgName, jname);
        return (jlong)0;
    }
    mctx->md_size = size;

    (*env)->ReleaseStringUTFChars(env, canonicalAlgName, jname);
    return (jlong)(uintptr_t)mctx;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_digest_DigestNIJNI_update
  (JNIEnv *env, jobject self, jlong ref, jbyteArray in, jint inOff, jint inLen)
{
    (void)self;
    if (ref == 0)
    {
        return (jint)JO_NOT_INITIALIZED;
    }
    if (in == NULL)
    {
        return (jint)JO_INPUT_IS_NULL;
    }
    if (inOff < 0)
    {
        return (jint)JO_INPUT_OFFSET_IS_NEGATIVE;
    }
    if (inLen < 0)
    {
        return (jint)JO_INPUT_LEN_IS_NEGATIVE;
    }
    jsize arrLen = (*env)->GetArrayLength(env, in);
    if ((jlong)inOff + (jlong)inLen > (jlong)arrLen)
    {
        return (jint)JO_INPUT_OUT_OF_RANGE;
    }
    if (inLen == 0)
    {
        return (jint)JO_SUCCESS;
    }

    jo_md_ctx *mctx = (jo_md_ctx *)(uintptr_t)ref;
    jboolean isCopy = JNI_FALSE;
    jbyte *data = (*env)->GetPrimitiveArrayCritical(env, in, &isCopy);
    if (data == NULL)
    {
        return (jint)JO_FAILED_ACCESS_INPUT;
    }
    const unsigned char *src = (const unsigned char *)(data + inOff);
    int ok = EVP_DigestUpdate(mctx->ctx, src, (size_t)inLen);
    (*env)->ReleasePrimitiveArrayCritical(env, in, data, 0);
    if (ok != 1)
    {
        return (jint)JO_OPENSSL_ERROR;
    }
    return (jint)JO_SUCCESS;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_digest_DigestNIJNI_doFinal
  (JNIEnv *env, jobject self, jlong ref, jbyteArray out, jint outOff)
{
    (void)self;
    if (ref == 0)
    {
        return (jint)JO_NOT_INITIALIZED;
    }
    if (out == NULL)
    {
        return (jint)JO_OUTPUT_IS_NULL;
    }
    if (outOff < 0)
    {
        return (jint)JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }
    jo_md_ctx *mctx = (jo_md_ctx *)(uintptr_t)ref;
    jsize outLen = (*env)->GetArrayLength(env, out);
    if (mctx->md_size < 0)
    {
        return (jint)JO_NOT_INITIALIZED;
    }
    if (outLen < mctx->md_size)
    {
        return (jint)JO_OUTPUT_TOO_SMALL;
    }
    if ((jlong)outOff + (jlong)mctx->md_size > (jlong)outLen)
    {
        return (jint)JO_OUTPUT_OUT_OF_RANGE;
    }

    jboolean isCopy = JNI_FALSE;
    jbyte *dst = (*env)->GetPrimitiveArrayCritical(env, out, &isCopy);
    if (dst == NULL)
    {
        return (jint)JO_FAILED_ACCESS_OUTPUT;
    }
    unsigned int written = 0;
    int ok = EVP_DigestFinal_ex(mctx->ctx, (unsigned char *)(dst + outOff), &written);
    (*env)->ReleasePrimitiveArrayCritical(env, out, dst, 0);
    if (ok != 1)
    {
        return (jint)JO_OPENSSL_ERROR;
    }
    if (EVP_DigestInit_ex(mctx->ctx, mctx->md, NULL) != 1)
    {
        return (jint)JO_OPENSSL_ERROR;
    }
    return (jint)written;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_digest_DigestNIJNI_getDigestLength
  (JNIEnv *env, jobject self, jlong ref)
{
    (void)env; (void)self;
    if (ref == 0)
    {
        return (jint)JO_NOT_INITIALIZED;
    }
    jo_md_ctx *mctx = (jo_md_ctx *)(uintptr_t)ref;
    return (jint)mctx->md_size;
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_digest_DigestNIJNI_reset
  (JNIEnv *env, jobject self, jlong ref)
{
    (void)env; (void)self;
    if (ref == 0)
    {
        return;
    }
    jo_md_ctx *mctx = (jo_md_ctx *)(uintptr_t)ref;
    (void)EVP_DigestInit_ex(mctx->ctx, mctx->md, NULL);
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_digest_DigestNIJNI_dispose
  (JNIEnv *env, jobject self, jlong ref)
{
    (void)env; (void)self;
    if (ref == 0)
    {
        return;
    }
    jo_md_ctx *mctx = (jo_md_ctx *)(uintptr_t)ref;
    if (mctx->ctx != NULL)
    {
        EVP_MD_CTX_free(mctx->ctx);
    }
    if (mctx->md != NULL && EVP_MD_get0_provider(mctx->md) != NULL)
    {
        EVP_MD_free((EVP_MD *)mctx->md);
    }
    OPENSSL_free(mctx);
}

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_digest_DigestNIJNI_copy
  (JNIEnv *env, jobject self, jlong ref)
{
    (void)env; (void)self;
    if (ref == 0)
    {
        return (jlong)0;
    }
    jo_md_ctx *src = (jo_md_ctx *)(uintptr_t)ref;
    jo_md_ctx *dst = (jo_md_ctx *)OPENSSL_zalloc(sizeof(jo_md_ctx));
    if (dst == NULL)
    {
        return (jlong)0;
    }
    dst->ctx = EVP_MD_CTX_new();
    if (dst->ctx == NULL)
    {
        OPENSSL_free(dst);
        return (jlong)0;
    }
    dst->md = src->md;
    if (dst->md != NULL && EVP_MD_get0_provider(dst->md) != NULL)
    {
        if (EVP_MD_up_ref((EVP_MD *)dst->md) != 1)
        {
            EVP_MD_CTX_free(dst->ctx);
            OPENSSL_free(dst);
            return (jlong)0;
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
        return (jlong)0;
    }
    dst->md_size = src->md_size;
    return (jlong)(uintptr_t)dst;
}

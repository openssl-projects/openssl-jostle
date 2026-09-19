//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI.h"
#include "bytearrays.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/ops.h"
#include "../util/x509.h"

/*
 * JNI bridge for X.509 certificate parsing. Every user-supplied pointer is
 * null-checked and every length range-checked HERE; util asserts them as
 * invariants. Returns identical codes to x509_ni_ffi.c for identical inputs.
 *
 * The certificate CEILING is a caller parameter rather than a constant util
 * enforces, so this layer owns the typed refusal above it. A deployment that
 * raises the configurable property gets a refusal, never an abort.
 */

/* The x509_handle a caller hands back. Null and kind are checked in util at
 * every entry point, never asserted: it is caller data. */
static x509_handle *handle_of(jlong ref)
{
    return (x509_handle *) (intptr_t) ref;
}

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1allocate
(JNIEnv *env, jobject jo, jbyteArray _der, jint off, jint len, jint maxBytes,
 jintArray _consumed, jintArray _err)
{
    UNUSED(jo);

    java_bytearray_ctx der;
    jint *err = NULL;
    jint *consumed = NULL;
    jlong result = 0;
    jint code = JO_FAIL;
    x509_handle *cert = NULL;
    int32_t used = 0;

    init_bytearray_ctx(&der);

    if (_err == NULL || _consumed == NULL)
    {
        /* Nothing to report through: the out-arrays are jostle's own plumbing,
         * so a null one is a programming error, not caller data. Asserting
         * BEFORE any pointer is taken, because GetIntArrayElements on a
         * zero-length array returns a valid pointer and the following store
         * would corrupt memory. */
        jo_assert(_err != NULL);
        jo_assert(_consumed != NULL);
    }
    jo_assert((*env)->GetArrayLength(env, _err) >= 1);
    jo_assert((*env)->GetArrayLength(env, _consumed) >= 1);

    err = (*env)->GetIntArrayElements(env, _err, NULL);
    if (err == NULL)
    {
        return 0;
    }
    consumed = (*env)->GetIntArrayElements(env, _consumed, NULL);
    if (consumed == NULL)
    {
        (*env)->ReleaseIntArrayElements(env, _err, err, 0);
        return 0;
    }

    if (_der == NULL)
    {
        code = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (off < 0)
    {
        code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }
    if (len < 0)
    {
        code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }
    if (maxBytes <= 0)
    {
        code = JO_CERT_MAX_BYTES_INVALID;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&der, env, _der))
    {
        code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    /* A null Java array loads as success with size 0, and a 0/0 range passes
     * every range check, so the loaded pointer is checked explicitly. */
    if (der.bytearray == NULL)
    {
        code = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (!check_bytearray_in_range(&der, off, len))
    {
        code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }
    /* Deliberately JO_CERT_DECODE_FAILED rather than the sibling bridges'
     * JO_INPUT_LEN_IS_NEGATIVE for a meaningless zero: an empty input IS a
     * failed certificate decode, and that wording is what a caller of
     * generateCertificate needs to read. */
    if (len == 0)
    {
        code = JO_CERT_DECODE_FAILED;
        goto exit;
    }
    /*
     * The ceiling, refused typed HERE. util asserts it, so this check is the
     * only thing standing between a raised property and a JVM abort.
     */
    if (len > maxBytes)
    {
        code = JO_CERT_TOO_LARGE;
        goto exit;
    }

    code = x509_cert_decode(der.bytearray + off, (size_t) len, (size_t) maxBytes, &cert, &used);
    if (code == JO_SUCCESS)
    {
        consumed[0] = used;
        result = (jlong) (intptr_t) cert;
    }

exit:
    err[0] = code;
    release_bytearray_ctx(&der);
    (*env)->ReleaseIntArrayElements(env, _consumed, consumed, 0);
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return result;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1fieldsLen
(JNIEnv *env, jobject jo, jlong ref)
{
    UNUSED(env);
    UNUSED(jo);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_cert_fields_len(handle_of(ref));
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1fields
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _blob, jintArray _sizes, jintArray _info)
{
    UNUSED(jo);

    java_bytearray_ctx blob;
    jint *sizes = NULL;
    jint *info = NULL;
    int32_t *nsizes = NULL;
    int32_t *ninfo = NULL;
    jint ret = JO_FAIL;
    int i;

    init_bytearray_ctx(&blob);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (_blob == NULL || _sizes == NULL || _info == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    if ((*env)->GetArrayLength(env, _sizes) < X509_SLOT_COUNT ||
        (*env)->GetArrayLength(env, _info) < X509_INFO_COUNT)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&blob, env, _blob))
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    /* load_bytearray_ctx reports SUCCESS for a null Java array, so the loaded
     * pointer is checked explicitly — the same shape as ni_allocate's input
     * check. Unreachable while _blob == NULL is refused above; kept so the
     * three entry points stay textually parallel if those checks separate. */
    if (blob.bytearray == NULL)
    {
        ret = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    nsizes = OPENSSL_malloc(sizeof(int32_t) * X509_SLOT_COUNT);
    ninfo = OPENSSL_malloc(sizeof(int32_t) * X509_INFO_COUNT);
    if (nsizes == NULL || ninfo == NULL)
    {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret = x509_cert_fields(handle_of(ref), blob.bytearray, blob.size, nsizes, ninfo);
    if (ret != JO_SUCCESS)
    {
        goto exit;
    }

    sizes = (*env)->GetIntArrayElements(env, _sizes, NULL);
    info = (*env)->GetIntArrayElements(env, _info, NULL);
    if (OPS_FAILED_ACCESS_2 (sizes == NULL || info == NULL))
    {
        ret = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    for (i = 0; i < X509_SLOT_COUNT; i++)
    {
        sizes[i] = nsizes[i];
    }
    for (i = 0; i < X509_INFO_COUNT; i++)
    {
        info[i] = ninfo[i];
    }

exit:
    if (sizes != NULL)
    {
        (*env)->ReleaseIntArrayElements(env, _sizes, sizes, 0);
    }
    if (info != NULL)
    {
        (*env)->ReleaseIntArrayElements(env, _info, info, 0);
    }
    OPENSSL_free(nsizes);
    OPENSSL_free(ninfo);
    release_bytearray_ctx(&blob);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1extensionsLen
(JNIEnv *env, jobject jo, jlong ref)
{
    UNUSED(env);
    UNUSED(jo);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_cert_extensions_len(handle_of(ref));
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1extensions
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _blob, jintArray _oidSizes,
 jintArray _valSizes, jintArray _critical)
{
    UNUSED(jo);

    java_bytearray_ctx blob;
    jint *oidSizes = NULL;
    jint *valSizes = NULL;
    jint *critical = NULL;
    int32_t *noid = NULL;
    int32_t *nval = NULL;
    int32_t *ncrit = NULL;
    jint ret = JO_FAIL;
    jsize count;
    jsize i;

    init_bytearray_ctx(&blob);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (_blob == NULL || _oidSizes == NULL || _valSizes == NULL || _critical == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    count = (*env)->GetArrayLength(env, _oidSizes);
    if ((*env)->GetArrayLength(env, _valSizes) != count ||
        (*env)->GetArrayLength(env, _critical) != count)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&blob, env, _blob))
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    if (blob.bytearray == NULL)
    {
        ret = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    /* util asserts the three arrays are non-NULL, so a zero capacity is
     * refused HERE rather than allowed to hand it NULL pointers. */
    if (count <= 0)
    {
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }
    {
        noid = OPENSSL_malloc(sizeof(int32_t) * (size_t) count);
        nval = OPENSSL_malloc(sizeof(int32_t) * (size_t) count);
        ncrit = OPENSSL_malloc(sizeof(int32_t) * (size_t) count);
        if (noid == NULL || nval == NULL || ncrit == NULL)
        {
            ret = JO_OPENSSL_ERROR;
            goto exit;
        }
    }

    ret = x509_cert_extensions(handle_of(ref), blob.bytearray, blob.size, (size_t) count,
                               noid, nval, ncrit);
    if (ret != JO_SUCCESS)
    {
        goto exit;
    }

    oidSizes = (*env)->GetIntArrayElements(env, _oidSizes, NULL);
    valSizes = (*env)->GetIntArrayElements(env, _valSizes, NULL);
    critical = (*env)->GetIntArrayElements(env, _critical, NULL);
    if (OPS_FAILED_ACCESS_3 (oidSizes == NULL || valSizes == NULL || critical == NULL))
    {
        ret = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    for (i = 0; i < count; i++)
    {
        oidSizes[i] = noid[i];
        valSizes[i] = nval[i];
        critical[i] = ncrit[i];
    }

exit:
    if (oidSizes != NULL)
    {
        (*env)->ReleaseIntArrayElements(env, _oidSizes, oidSizes, 0);
    }
    if (valSizes != NULL)
    {
        (*env)->ReleaseIntArrayElements(env, _valSizes, valSizes, 0);
    }
    if (critical != NULL)
    {
        (*env)->ReleaseIntArrayElements(env, _critical, critical, 0);
    }
    OPENSSL_free(noid);
    OPENSSL_free(nval);
    OPENSSL_free(ncrit);
    release_bytearray_ctx(&blob);
    return ret;
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1dispose
(JNIEnv *env, jobject jo, jlong ref)
{
    UNUSED(env);
    UNUSED(jo);

    if (ref == 0)
    {
        return;
    }
    x509_cert_free(handle_of(ref));
}

/* ---------------------------------------------------------------- CRLs --- */

static x509_handle *crl_of(jlong ref)
{
    return (x509_handle *) (intptr_t) ref;
}

/*
 * Shared by every CRL entry point that fills an int array pair, so the
 * capacity rule and the copy-back are written once rather than per function.
 */
static jint fill_int_arrays(JNIEnv *env, jintArray a, const int32_t *src, jsize n)
{
    jint *p;
    jsize i;

    /*
     * Checked HERE, and before the pointer is taken, even though every caller
     * already checks. GetIntArrayElements on a short array returns a valid
     * pointer to a short buffer, so the loop below would store past its end -
     * measured elsewhere in this tree as a JVM SIGBUS. Relying on the callers
     * makes this function's memory-safety an invariant maintained in another
     * function, which the next caller is free to break.
     */
    if ((*env)->GetArrayLength(env, a) < n)
    {
        return JO_OUTPUT_TOO_SMALL;
    }

    p = (*env)->GetIntArrayElements(env, a, NULL);

    if (OPS_FAILED_ACCESS_2 p == NULL)
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    for (i = 0; i < n; i++)
    {
        p[i] = src[i];
    }
    (*env)->ReleaseIntArrayElements(env, a, p, 0);
    return JO_SUCCESS;
}

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1allocateCrl
(JNIEnv *env, jobject jo, jbyteArray _der, jint off, jint len, jint maxBytes,
 jintArray _consumed, jintArray _err)
{
    UNUSED(jo);

    java_bytearray_ctx der;
    jint *err = NULL;
    jint *consumed = NULL;
    jlong result = 0;
    jint code = JO_FAIL;
    x509_handle *crl = NULL;
    int32_t used = 0;

    init_bytearray_ctx(&der);

    jo_assert(_err != NULL);
    jo_assert(_consumed != NULL);
    jo_assert((*env)->GetArrayLength(env, _err) >= 1);
    jo_assert((*env)->GetArrayLength(env, _consumed) >= 1);

    err = (*env)->GetIntArrayElements(env, _err, NULL);
    if (err == NULL)
    {
        return 0;
    }
    consumed = (*env)->GetIntArrayElements(env, _consumed, NULL);
    if (consumed == NULL)
    {
        (*env)->ReleaseIntArrayElements(env, _err, err, 0);
        return 0;
    }

    if (_der == NULL)
    {
        code = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (off < 0)
    {
        code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }
    if (len < 0)
    {
        code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }
    if (maxBytes <= 0)
    {
        code = JO_CERT_MAX_BYTES_INVALID;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&der, env, _der))
    {
        code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (der.bytearray == NULL)
    {
        code = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (!check_bytearray_in_range(&der, off, len))
    {
        code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }
    if (len == 0)
    {
        code = JO_CRL_DECODE_FAILED;
        goto exit;
    }
    if (len > maxBytes)
    {
        /* The CRL ceiling, not the certificate one: the two are deliberately
         * different sizes and the refusal names the property that moves THIS
         * bound. */
        code = JO_CRL_TOO_LARGE;
        goto exit;
    }

    code = x509_crl_decode(der.bytearray + off, (size_t) len, (size_t) maxBytes, &crl, &used);
    if (code == JO_SUCCESS)
    {
        consumed[0] = used;
        result = (jlong) (intptr_t) crl;
    }

exit:
    err[0] = code;
    release_bytearray_ctx(&der);
    (*env)->ReleaseIntArrayElements(env, _consumed, consumed, 0);
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return result;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlFieldsLen
(JNIEnv *env, jobject jo, jlong ref)
{
    UNUSED(env);
    UNUSED(jo);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_crl_fields_len(crl_of(ref));
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlFields
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _blob, jintArray _sizes, jintArray _info)
{
    UNUSED(jo);

    java_bytearray_ctx blob;
    int32_t nsizes[X509_CRL_SLOT_COUNT];
    int32_t ninfo[X509_CRL_INFO_COUNT];
    jint ret;

    init_bytearray_ctx(&blob);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (_blob == NULL || _sizes == NULL || _info == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    if ((*env)->GetArrayLength(env, _sizes) < X509_CRL_SLOT_COUNT ||
        (*env)->GetArrayLength(env, _info) < X509_CRL_INFO_COUNT)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&blob, env, _blob))
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    if (blob.bytearray == NULL)
    {
        release_bytearray_ctx(&blob);
        return JO_OUTPUT_IS_NULL;
    }

    ret = x509_crl_fields(crl_of(ref), blob.bytearray, blob.size, nsizes, ninfo);
    release_bytearray_ctx(&blob);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    ret = fill_int_arrays(env, _sizes, nsizes, X509_CRL_SLOT_COUNT);
    if (ret != JO_SUCCESS)
    {
        return ret;
    }
    return fill_int_arrays(env, _info, ninfo, X509_CRL_INFO_COUNT);
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlExtensionsLen
(JNIEnv *env, jobject jo, jlong ref)
{
    UNUSED(env);
    UNUSED(jo);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_crl_extensions_len(crl_of(ref));
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlExtensions
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _blob, jintArray _oidSizes,
 jintArray _valSizes, jintArray _critical)
{
    UNUSED(jo);

    java_bytearray_ctx blob;
    int32_t *noid = NULL;
    int32_t *nval = NULL;
    int32_t *ncrit = NULL;
    jint ret;
    jsize count;

    init_bytearray_ctx(&blob);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (_blob == NULL || _oidSizes == NULL || _valSizes == NULL || _critical == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    count = (*env)->GetArrayLength(env, _oidSizes);
    if ((*env)->GetArrayLength(env, _valSizes) != count ||
        (*env)->GetArrayLength(env, _critical) != count || count <= 0)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&blob, env, _blob))
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    if (blob.bytearray == NULL)
    {
        release_bytearray_ctx(&blob);
        return JO_OUTPUT_IS_NULL;
    }

    noid = OPENSSL_malloc(sizeof(int32_t) * (size_t) count);
    nval = OPENSSL_malloc(sizeof(int32_t) * (size_t) count);
    ncrit = OPENSSL_malloc(sizeof(int32_t) * (size_t) count);
    if (noid == NULL || nval == NULL || ncrit == NULL)
    {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret = x509_crl_extensions(crl_of(ref), blob.bytearray, blob.size, (size_t) count,
                              noid, nval, ncrit);
    if (ret != JO_SUCCESS)
    {
        goto exit;
    }
    ret = fill_int_arrays(env, _oidSizes, noid, count);
    if (ret == JO_SUCCESS)
    {
        ret = fill_int_arrays(env, _valSizes, nval, count);
    }
    if (ret == JO_SUCCESS)
    {
        ret = fill_int_arrays(env, _critical, ncrit, count);
    }

exit:
    OPENSSL_free(noid);
    OPENSSL_free(nval);
    OPENSSL_free(ncrit);
    release_bytearray_ctx(&blob);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlEntriesLen
(JNIEnv *env, jobject jo, jlong ref)
{
    UNUSED(env);
    UNUSED(jo);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    return x509_crl_entries_len(crl_of(ref));
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1crlEntries
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _blob, jintArray _sizes, jintArray _dates)
{
    UNUSED(jo);

    java_bytearray_ctx blob;
    int32_t *nsizes = NULL;
    int32_t *ndates = NULL;
    jint ret;
    jsize count;

    init_bytearray_ctx(&blob);

    if (ref == 0)
    {
        return JO_CERT_CTX_IS_NULL;
    }
    if (_blob == NULL || _sizes == NULL || _dates == NULL)
    {
        return JO_OUTPUT_IS_NULL;
    }
    count = (*env)->GetArrayLength(env, _sizes);
    /* dates carries a high/low pair per entry, so its length is twice the
     * entry count; a mismatch is a caller error, not something util should
     * discover. */
    if (count <= 0 || (*env)->GetArrayLength(env, _dates) != 2 * count)
    {
        return JO_OUTPUT_TOO_SMALL;
    }
    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&blob, env, _blob))
    {
        return JO_FAILED_ACCESS_OUTPUT;
    }
    if (blob.bytearray == NULL)
    {
        release_bytearray_ctx(&blob);
        return JO_OUTPUT_IS_NULL;
    }

    nsizes = OPENSSL_malloc(sizeof(int32_t) * (size_t) count);
    ndates = OPENSSL_malloc(sizeof(int32_t) * 2 * (size_t) count);
    if (nsizes == NULL || ndates == NULL)
    {
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret = x509_crl_entries(crl_of(ref), blob.bytearray, blob.size, (size_t) count,
                           nsizes, ndates);
    if (ret != JO_SUCCESS)
    {
        goto exit;
    }
    ret = fill_int_arrays(env, _sizes, nsizes, count);
    if (ret == JO_SUCCESS)
    {
        ret = fill_int_arrays(env, _dates, ndates, 2 * count);
    }

exit:
    OPENSSL_free(nsizes);
    OPENSSL_free(ndates);
    release_bytearray_ctx(&blob);
    return ret;
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_cert_X509ServiceJNI_ni_1disposeCrl
(JNIEnv *env, jobject jo, jlong ref)
{
    UNUSED(env);
    UNUSED(jo);

    if (ref == 0)
    {
        return;
    }
    x509_crl_free(crl_of(ref));
}

//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "org_openssl_jostle_jcajce_provider_certpath_CertPathServiceJNI.h"
#include "bytearrays.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/certpath.h"
#include "../util/jo_assert.h"

/*
 * JNI bridge for certification path validation. Every user-supplied pointer is
 * null-checked and every length range-checked HERE; util asserts them as
 * invariants. Returns identical codes to certpath_ni_ffi.c for identical
 * inputs.
 *
 * The certificate count is bounded before any allocation: a path longer than
 * this is a caller error, not a resource question, and the bound keeps
 * count * sizeof(int32_t) far from overflow.
 */
#define MAX_CERTS 256

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_certpath_CertPathServiceJNI_ni_1verify
(JNIEnv *env, jobject jo, jbyteArray _der, jintArray _sizes, jint count, jint anchorCount,
 jlong timeSecs, jint strict, jbyteArray _chainOut, jintArray _outInfo)
{
    UNUSED(jo);

    java_bytearray_ctx der;
    java_bytearray_ctx chainOut;
    jint ret = JO_FAIL;
    jint *sizes = NULL;
    int32_t *native_sizes = NULL;
    certpath_result result;
    int32_t i;

    init_bytearray_ctx(&der);
    init_bytearray_ctx(&chainOut);
    memset(&result, 0, sizeof(result));

    if (_der == NULL)
    {
        ret = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (_sizes == NULL || _outInfo == NULL || _chainOut == NULL)
    {
        ret = JO_OUTPUT_IS_NULL;
        goto exit;
    }
    if (count < 2 || anchorCount < 1 || anchorCount >= count)
    {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }
    if (count > MAX_CERTS)
    {
        ret = JO_INPUT_TOO_LONG_INT32;
        goto exit;
    }
    if ((*env)->GetArrayLength(env, _sizes) < count)
    {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }
    if ((*env)->GetArrayLength(env, _outInfo) < count + 3)
    {
        ret = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (!load_bytearray_ctx(&der, env, _der))
    {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (der.bytearray == NULL)
    {
        /* load_bytearray_ctx succeeds for a NULL Java array, so this is the
           check that separates a null input from an empty one. */
        ret = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (der.size == 0)
    {
        ret = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }
    if (!load_bytearray_ctx(&chainOut, env, _chainOut))
    {
        ret = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    if (chainOut.bytearray == NULL)
    {
        ret = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    sizes = (*env)->GetIntArrayElements(env, _sizes, NULL);
    if (sizes == NULL)
    {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    native_sizes = OPENSSL_malloc(sizeof(int32_t) * (size_t) count);
    if (native_sizes == NULL)
    {
        ret = JO_FAIL;
        goto exit;
    }
    {
        size_t total = 0;
        for (i = 0; i < count; i++)
        {
            if (sizes[i] <= 0)
            {
                ret = JO_INPUT_LEN_IS_NEGATIVE;
                goto exit;
            }
            total += (size_t) sizes[i];
            if (total > der.size)
            {
                ret = JO_INPUT_OUT_OF_RANGE;
                goto exit;
            }
            native_sizes[i] = (int32_t) sizes[i];
        }
    }

    ret = certpath_verify(der.bytearray, der.size, native_sizes, count, anchorCount,
                          (int64_t) timeSecs, strict, &result);
    if (ret != JO_SUCCESS)
    {
        if (ret == JO_CERT_DECODE_FAILED)
        {
            /* Report WHICH certificate, so the Java layer can name it. */
            jint header[3];
            header[0] = (jint) ret;
            header[1] = (jint) result.depth;
            header[2] = 0;
            (*env)->SetIntArrayRegion(env, _outInfo, 0, 3, header);
        }
        goto exit;
    }

    if (result.chain_len > chainOut.size)
    {
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }
    if (result.chain_len > 0)
    {
        memcpy(chainOut.bytearray, result.chain_der, result.chain_len);
    }

    {
        jint header[3];
        header[0] = (jint) result.error;
        header[1] = (jint) result.depth;
        header[2] = (jint) result.chain_count;
        (*env)->SetIntArrayRegion(env, _outInfo, 0, 3, header);
        for (i = 0; i < result.chain_count; i++)
        {
            jint sz = (jint) result.chain_sizes[i];
            (*env)->SetIntArrayRegion(env, _outInfo, 3 + i, 1, &sz);
        }
    }

exit:
    certpath_result_free(&result);
    OPENSSL_free(native_sizes);
    if (sizes != NULL)
    {
        (*env)->ReleaseIntArrayElements(env, _sizes, sizes, JNI_ABORT);
    }
    release_bytearray_ctx(&chainOut);
    release_bytearray_ctx(&der);
    return ret;
}

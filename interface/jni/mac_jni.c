//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <jni.h>
#include <stdint.h>

#include "bytearrays.h"
#include "byte_array_critical.h"
#include "types.h"
#include "../util/mac.h"
#include "../util/ops.h"

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1allocateMac
  (JNIEnv *env, jobject self, jstring macName, jstring canonicalDigestName, jintArray err)
{
    const char *mac_name;
    const char *name;
    uintptr_t ref = 0;
    int32_t ret;

    UNUSED(self);

    if (macName == NULL || canonicalDigestName == NULL)
    {
        if (err != NULL)
        {
            jint e = JO_NAME_IS_NULL;
            (*env)->SetIntArrayRegion(env, err, 0, 1, &e);
        }
        return (jlong)0;
    }

    mac_name = (*env)->GetStringUTFChars(env, macName, NULL);
    if (OPS_FAILED_ACCESS_1 mac_name == NULL)
    {
        if (err != NULL)
        {
            jint e = JO_UNABLE_TO_ACCESS_NAME;
            (*env)->SetIntArrayRegion(env, err, 0, 1, &e);
        }
        return (jlong)0;
    }

    name = (*env)->GetStringUTFChars(env, canonicalDigestName, NULL);
    if (OPS_FAILED_ACCESS_1 name == NULL)
    {
        (*env)->ReleaseStringUTFChars(env, macName, mac_name);
        if (err != NULL)
        {
            jint e = JO_UNABLE_TO_ACCESS_NAME;
            (*env)->SetIntArrayRegion(env, err, 0, 1, &e);
        }
        return (jlong)0;
    }

    ret = jo_mac_new(mac_name, name, &ref);
    (*env)->ReleaseStringUTFChars(env, macName, mac_name);
    (*env)->ReleaseStringUTFChars(env, canonicalDigestName, name);
    if (err != NULL)
    {
        jint e = ret;
        (*env)->SetIntArrayRegion(env, err, 0, 1, &e);
    }
    if (ret < 0)
    {
        return (jlong)0;
    }

    return (jlong)ref;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1init
  (JNIEnv *env, jobject self, jlong ref, jbyteArray keyBytes)
{
    critical_bytearray_ctx key;
    int32_t ret;

    UNUSED(self);

    init_critical_ctx(&key, env, keyBytes);
    if (key.array == NULL)
    {
        ret = JO_KEY_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&key))
    {
        ret = JO_FAILED_ACCESS_KEY;
        goto exit;
    }

    ret = jo_mac_init((uintptr_t)ref, key.critical, key.size);

exit:
    release_critical_ctx(&key);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1updateByte
  (JNIEnv *env, jobject self, jlong ref, jbyte in)
{
    int32_t ret;
    uint8_t b;

    UNUSED(env);
    UNUSED(self);

    b = (uint8_t)in;
    ret = jo_mac_update((uintptr_t)ref, &b, 0, 1);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1updateBytes
  (JNIEnv *env, jobject self, jlong ref, jbyteArray in, jint inOff, jint inLen)
{
    critical_bytearray_ctx input;
    int32_t ret;

    UNUSED(self);

    init_critical_ctx(&input, env, in);
    if (input.array == NULL)
    {
        ret = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (inOff < 0)
    {
        ret = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }
    if (inLen < 0)
    {
        ret = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }
    if (!check_critical_in_range(&input, inOff, inLen))
    {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_2 !load_critical_ctx(&input))
    {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ret = jo_mac_update((uintptr_t)ref, input.critical, inOff, inLen);

exit:
    release_critical_ctx(&input);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1doFinal
  (JNIEnv *env, jobject self, jlong ref, jbyteArray out, jint outOff)
{
    critical_bytearray_ctx output;
    int32_t ret;

    UNUSED(self);

    init_critical_ctx(&output, env, out);
    if (output.array == NULL)
    {
        ret = JO_OUTPUT_IS_NULL;
        goto exit;
    }
    if (outOff < 0)
    {
        ret = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_3 !load_critical_ctx(&output))
    {
        ret = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret = jo_mac_final((uintptr_t)ref, output.critical, outOff, (int32_t)output.size);

exit:
    release_critical_ctx(&output);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1getMacLength
  (JNIEnv *env, jobject self, jlong ref)
{
    UNUSED(env);
    UNUSED(self);
    return jo_mac_len((uintptr_t)ref);
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1reset
  (JNIEnv *env, jobject self, jlong ref)
{
    UNUSED(env);
    UNUSED(self);
    jo_mac_reset((uintptr_t)ref);
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1dispose
  (JNIEnv *env, jobject self, jlong ref)
{
    UNUSED(env);
    UNUSED(self);



    jo_mac_free((uintptr_t)ref);
}

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1copy
  (JNIEnv *env, jobject self, jlong ref, jintArray err)
{
    uintptr_t out_ref = 0;
    int32_t ret;

    UNUSED(env);
    UNUSED(self);

    ret = jo_mac_copy((uintptr_t)ref, &out_ref);
    if (err != NULL)
    {
        jint e = ret;
        (*env)->SetIntArrayRegion(env, err, 0, 1, &e);
    }
    if (ret < 0)
    {
        return (jlong)0;
    }
    return (jlong)out_ref;
}

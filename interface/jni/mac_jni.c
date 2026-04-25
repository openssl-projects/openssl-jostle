//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <jni.h>
#include <stdint.h>

#include "byte_array_critical.h"
#include "types.h"
#include "../util/mac.h"
#include "../util/ops.h"
#include "../util/jo_assert.h"
#include "org_openssl_jostle_jcajce_provider_mac_MacServiceJNI.h"

JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1allocateMac
(JNIEnv *env, jobject self, jstring _macName, jstring _functionName, jintArray _err) {
    const char *mac_name = NULL;
    const char *function = NULL;
    int32_t *err = NULL;
    mac_ctx *mac_ctx = NULL;


    UNUSED(self);

    //
    // err needs to be defined and accessible
    //
    jo_assert(_err != NULL);
    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);


    if (_macName == NULL) {
        *err = JO_NAME_IS_NULL;
        goto exit;
    }

    if (_functionName == NULL) {
        *err = JO_MAC_FUNCTION_IS_NULL;
        goto exit;
    }


    mac_name = (*env)->GetStringUTFChars(env, _macName, NULL);
    if (OPS_FAILED_ACCESS_1 mac_name == NULL) {
        *err = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    function = (*env)->GetStringUTFChars(env, _functionName, NULL);
    if (OPS_FAILED_ACCESS_2 function == NULL) {
        *err = JO_UNABLE_TO_ACCESS_FUNCTION;
        goto exit;
    }

    mac_ctx = allocate_mac(mac_name, function, err);
    if (UNSUCCESSFUL(*err)) {
        goto exit;
    }
    *err = JO_SUCCESS;

exit:

    if (mac_name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _macName, mac_name);
    }

    if (function != NULL) {
        (*env)->ReleaseStringUTFChars(env, _functionName, function);
    }

    (*env)->ReleaseIntArrayElements(env, _err, err, 0);

    return (jlong) mac_ctx;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1init
(JNIEnv *env, jobject self, jlong ref, jbyteArray keyBytes) {
    UNUSED(self);

    mac_ctx *mac_ctx = (void *) ref;
    critical_bytearray_ctx key;
    int32_t ret;

    jo_assert(mac_ctx != NULL);


    init_critical_ctx(&key, env, keyBytes);
    if (key.array == NULL) {
        ret = JO_KEY_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&key)) {
        ret = JO_FAILED_ACCESS_KEY;
        goto exit;
    }

    ret = mac_init(mac_ctx, key.critical, key.size);

exit:
    release_critical_ctx(&key);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1updateByte
(JNIEnv *env, jobject self, jlong ref, jbyte in) {
    UNUSED(env);
    UNUSED(self);

    mac_ctx *mac_ctx = (void *) ref;
    int32_t ret;
    uint8_t b;

    jo_assert(mac_ctx != NULL);

    if (!mac_ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    b = (uint8_t) in;
    ret = mac_update(mac_ctx, &b, 0, 1);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1updateBytes
(JNIEnv *env, jobject self, jlong ref, jbyteArray in, jint inOff, jint inLen) {
    UNUSED(self);

    mac_ctx *mac_ctx = (void *) ref;
    critical_bytearray_ctx input;
    int32_t ret;

    if (!mac_ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    init_critical_ctx(&input, env, in);
    if (input.array == NULL) {
        ret = JO_INPUT_IS_NULL;
        goto exit;
    }
    if (inOff < 0) {
        ret = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }
    if (inLen < 0) {
        ret = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }
    if (!check_critical_in_range(&input, inOff, inLen)) {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&input)) {
        ret = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ret = mac_update(mac_ctx, input.critical, inOff, inLen);

exit:
    release_critical_ctx(&input);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1doFinal
(JNIEnv *env, jobject self, jlong ref, jbyteArray _out, jint outOff) {
    UNUSED(self);

    mac_ctx *mac_ctx = (void *) ref;
    jo_assert(mac_ctx != NULL);

    if (!mac_ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    if (_out == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (outOff < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }

    int32_t m_len = mac_len(mac_ctx);
    if (UNSUCCESSFUL(m_len)) {
        return m_len;
    }


    critical_bytearray_ctx output;
    int32_t ret;
    init_critical_ctx(&output, env, _out);

    if (!check_critical_in_range(&output, outOff, m_len)) {
        ret = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&output)) {
        ret = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret = mac_final(mac_ctx, output.critical, outOff, (int32_t) output.size);

exit:
    release_critical_ctx(&output);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1getMacLength
(JNIEnv *env, jobject self, jlong ref) {
    UNUSED(env);
    UNUSED(self);

    mac_ctx *ctx = (void *) ref;
    jo_assert(ctx != NULL);

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    return mac_len(ctx);
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1reset
(JNIEnv *env, jobject self, jlong ref) {
    UNUSED(env);
    UNUSED(self);

    mac_ctx *ctx = (void *) ref;
    if (ctx == NULL) {
        // Observed spurious resets from within the JVMs provider logic in the past.
        return JO_SUCCESS;
    }

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

   return  mac_reset(ctx);
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1dispose
(JNIEnv *env, jobject self, jlong ref) {
    UNUSED(env);
    UNUSED(self);

    mac_ctx *ctx = (void *) ref;

    mac_free(ctx);
}

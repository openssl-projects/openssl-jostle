//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <jni.h>
#include <stdint.h>

#include "byte_array_critical.h"
#include "secret_bytearrays.h"
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

    // err is ours; a zero-length array would write out of bounds.
    jo_assert(_err != NULL);
    jo_assert((*env)->GetArrayLength(env, _err) >= 1);
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

    if (modified_utf8_names_nothing(mac_name)) {
        *err = JO_NAME_NOT_FOUND;
        goto exit;
    }

    if (modified_utf8_names_nothing(function)) {
        *err = JO_MAC_FUNCTION_NOT_FOUND;
        goto exit;
    }

    mac_ctx = allocate_mac(mac_name, function, err);

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

/*
 * Class:     org_openssl_jostle_jcajce_provider_mac_MacServiceJNI
 * Method:    ni_copyMac
 * Signature: (J[I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1copyMac
(JNIEnv *env, jobject self, jlong ref, jintArray _err) {
    UNUSED(self);

    int32_t *err = NULL;
    mac_ctx *new_ctx = NULL;

    // err is ours; a zero-length array would write out of bounds.
    jo_assert(_err != NULL);
    jo_assert((*env)->GetArrayLength(env, _err) >= 1);
    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);

    // mac_copy refuses a NULL or foreign handle with a typed code.
    new_ctx = mac_copy((mac_ctx *) ref, err);

    (*env)->ReleaseIntArrayElements(env, _err, err, 0);

    return (jlong) new_ctx;
}


/*
 * ivBytes carries GMAC's nonce and customBytes KMAC's customisation string; either may be null, and the MAC's arm
 * in init_mac_ctx decides whether it needs one. outLen 0 means unspecified. The key is copied and cleansed at
 * release; iv and custom are not secret.
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1init
(JNIEnv *env, jobject self, jlong ref, jbyteArray keyBytes, jbyteArray ivBytes,
 jbyteArray customBytes, jint outLen) {
    UNUSED(self);

    mac_ctx *mac_ctx = (void *) ref;
    int32_t ret = mac_ctx_check(mac_ctx);
    if (UNSUCCESSFUL(ret)) {
        return ret;
    }

    java_secret_bytearray_ctx key;
    critical_bytearray_ctx iv;
    critical_bytearray_ctx custom;

    init_secret_bytearray_ctx(&key);
    init_critical_ctx(&iv, env, ivBytes);
    init_critical_ctx(&custom, env, customBytes);

    if (keyBytes == NULL) {
        ret = JO_KEY_IS_NULL;
        goto exit;
    }

    if (outLen < 0) {
        ret = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_3 !load_secret_input_ctx(&key, env, keyBytes)) {
        ret = JO_FAILED_ACCESS_KEY;
        goto exit;
    }

    if (iv.array != NULL && (OPS_FAILED_ACCESS_5 !load_critical_ctx(&iv))) {
        ret = JO_FAILED_ACCESS_IV;
        goto exit;
    }

    if (custom.array != NULL && (OPS_FAILED_ACCESS_6 !load_critical_ctx(&custom))) {
        ret = JO_FAILED_ACCESS_CUSTOM;
        goto exit;
    }

    ret = mac_init(mac_ctx, key.bytearray, key.size,
                   iv.array == NULL ? NULL : iv.critical, iv.size,
                   custom.array == NULL ? NULL : custom.critical, custom.size,
                   (size_t) outLen);

exit:
    release_critical_ctx(&custom);
    release_critical_ctx(&iv);
    release_secret_bytearray_ctx(&key);
    return ret;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1updateByte
(JNIEnv *env, jobject self, jlong ref, jbyte in) {
    UNUSED(env);
    UNUSED(self);

    mac_ctx *mac_ctx = (void *) ref;
    int32_t ret = mac_ctx_check(mac_ctx);
    if (UNSUCCESSFUL(ret)) {
        return ret;
    }

    uint8_t b;

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
    int32_t ret = mac_ctx_check(mac_ctx);
    if (UNSUCCESSFUL(ret)) {
        return ret;
    }

    critical_bytearray_ctx input;

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

    if (OPS_FAILED_ACCESS_4 !load_critical_ctx(&input)) {
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
    int32_t check_rc = mac_ctx_check(mac_ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

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

    if (OPS_INT32_OVERFLOW_2 output.size > INT32_MAX) {
        ret = JO_OUTPUT_SIZE_INT_OVERFLOW;
        goto exit;
    }

    if (!check_critical_in_range(&output, outOff, m_len)) {
        ret = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_7 !load_critical_ctx(&output)) {
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
    int32_t check_rc = mac_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    if (!ctx->initialized) {
        return JO_NOT_INITIALIZED;
    }

    return mac_len(ctx);
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1macLengthMeta
(JNIEnv *env, jobject self, jlong ref) {
    UNUSED(env);
    UNUSED(self);

    mac_ctx *ctx = (void *) ref;
    int32_t check_rc = mac_ctx_check(ctx);
    if (UNSUCCESSFUL(check_rc)) {
        return check_rc;
    }

    // Keyless: answers before init.
    return mac_len_for(ctx);
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1reset
(JNIEnv *env, jobject self, jlong ref) {
    UNUSED(env);
    UNUSED(self);

    // mac_reset refuses a NULL or foreign handle, and an uninitialised one.
    return mac_reset((mac_ctx *) ref);
}

JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_mac_MacServiceJNI_ni_1dispose
(JNIEnv *env, jobject self, jlong ref) {
    UNUSED(env);
    UNUSED(self);

    // mac_free frees nothing on a NULL or wrong kind.
    mac_free((mac_ctx *) ref);
}

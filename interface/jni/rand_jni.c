//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_rand_RandServiceJNI.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/ops.h"
#include "../util/rand.h"

static int rand_strength_supported(int32_t strength) {
    return strength >= 0 && strength <= JO_RAND_MAX_STRENGTH;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_rand_RandServiceJNI
 * Method:    ni_createContext
 * Signature: (IZ[B[I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1createContext
  (JNIEnv *env, jobject jo, jstring _mechanism, jstring _variant, jboolean use_df,
   jint strength, jboolean prediction_resistant,
   jbyteArray _personalization_string, jintArray _err)
{
    UNUSED(jo);

    int32_t *err = NULL;
    JO_RAND_CTX *ctx = NULL;
    const char *mechanism = NULL;
    const char *variant = NULL;
    java_bytearray_ctx personalization_string;
    init_bytearray_ctx(&personalization_string);

    jo_assert(_err != NULL);
    err = (*env)->GetIntArrayElements(env, _err, NULL);
    jo_assert(err != NULL);

    if (_mechanism == NULL || _variant == NULL) {
        err[0] = JO_NAME_IS_NULL;
        goto exit;
    }

    mechanism = (*env)->GetStringUTFChars(env, _mechanism, NULL);
    if (mechanism == NULL) {
        err[0] = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    variant = (*env)->GetStringUTFChars(env, _variant, NULL);
    if (variant == NULL) {
        err[0] = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    if (!rand_strength_supported(strength)) {
        err[0] = JO_RAND_INSUFFICIENT_STRENGTH;
        goto exit;
    }

    if (_personalization_string != NULL
        && (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&personalization_string, env, _personalization_string))) {
        err[0] = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ctx = rand_ctx_create(mechanism, variant, use_df == JNI_TRUE,
                          strength, prediction_resistant == JNI_TRUE,
                          personalization_string.bytearray,
                          personalization_string.size, err);

exit:
    release_bytearray_ctx(&personalization_string);
    if (variant != NULL) {
        (*env)->ReleaseStringUTFChars(env, _variant, variant);
    }
    if (mechanism != NULL) {
        (*env)->ReleaseStringUTFChars(env, _mechanism, mechanism);
    }
    (*env)->ReleaseIntArrayElements(env, _err, err, 0);
    return (jlong) ctx;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_rand_RandServiceJNI
 * Method:    ni_disposeContext
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1disposeContext
  (JNIEnv *env, jobject jo, jlong ref)
{
    UNUSED(env);
    UNUSED(jo);

    rand_ctx_destroy((JO_RAND_CTX *) ref);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_rand_RandServiceJNI
 * Method:    ni_contextRandomBytes
 * Signature: (J[BIIZ[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1contextRandomBytes
  (JNIEnv *env, jobject jo, jlong ref, jbyteArray _output, jint output_len, jint strength,
   jboolean prediction_resistant, jbyteArray _additional_input)
{
    UNUSED(jo);

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx output;
    java_bytearray_ctx additional_input;
    init_bytearray_ctx(&output);
    init_bytearray_ctx(&additional_input);

    if (ref == 0) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (_output == NULL) {
        ret_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (output_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!rand_strength_supported(strength)) {
        ret_code = JO_RAND_INSUFFICIENT_STRENGTH;
        goto exit;
    }

    if (output_len == 0) {
        ret_code = JO_SUCCESS;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    if (_additional_input != NULL
        && (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&additional_input, env, _additional_input))) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if ((size_t) output_len > output.size) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    ret_code = rand_ctx_random_bytes((JO_RAND_CTX *) ref, output.bytearray,
                                     output_len, strength,
                                     prediction_resistant == JNI_TRUE,
                                     additional_input.bytearray,
                                     additional_input.size);

exit:
    release_bytearray_ctx(&additional_input);
    release_bytearray_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_rand_RandServiceJNI
 * Method:    ni_contextReseed
 * Signature: (JIZ[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1contextReseed
  (JNIEnv *env, jobject jo, jlong ref, jint strength, jboolean prediction_resistant,
   jbyteArray _additional_input)
{
    UNUSED(jo);

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx additional_input;
    init_bytearray_ctx(&additional_input);

    if (ref == 0) {
        ret_code = JO_NOT_INITIALIZED;
        goto exit;
    }

    if (!rand_strength_supported(strength)) {
        ret_code = JO_RAND_INSUFFICIENT_STRENGTH;
        goto exit;
    }

    if (_additional_input != NULL
        && (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&additional_input, env, _additional_input))) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    ret_code = rand_ctx_reseed((JO_RAND_CTX *) ref, strength,
                               prediction_resistant == JNI_TRUE,
                               additional_input.bytearray,
                               additional_input.size);

exit:
    release_bytearray_ctx(&additional_input);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_rand_RandServiceJNI
 * Method:    ni_drbgStrength
 * Signature: (Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rand_RandServiceJNI_ni_1drbgStrength
  (JNIEnv *env, jobject jo, jstring _mechanism, jstring _variant)
{
    UNUSED(jo);

    int32_t ret_code = JO_FAIL;
    const char *mechanism = NULL;
    const char *variant = NULL;

    if (_mechanism == NULL || _variant == NULL) {
        ret_code = JO_NAME_IS_NULL;
        goto exit;
    }

    mechanism = (*env)->GetStringUTFChars(env, _mechanism, NULL);
    if (mechanism == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    variant = (*env)->GetStringUTFChars(env, _variant, NULL);
    if (variant == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    ret_code = rand_drbg_strength(mechanism, variant);

exit:
    if (variant != NULL) {
        (*env)->ReleaseStringUTFChars(env, _variant, variant);
    }
    if (mechanism != NULL) {
        (*env)->ReleaseStringUTFChars(env, _mechanism, mechanism);
    }
    return ret_code;
}

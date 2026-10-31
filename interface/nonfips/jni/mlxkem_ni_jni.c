//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "bytearrays.h"
#include "secret_bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/mlxkem.h"
#include "../util/ops.h"

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI
 * Method:    ni_generateKeyPair
 * Signature: (I[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1generateKeyPair
(JNIEnv *env, jobject jo, jint type, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);

    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *key_spec = NULL;

    if (rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    key_spec = create_spec();
    ret_val = mlxkem_generate_key_pair(key_spec, type, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(key_spec);
        key_spec = NULL;
    }

exit:
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) key_spec;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI
 * Method:    ni_getPublicKey
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1getPublicKey
(JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    int32_t ret_code = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    java_bytearray_ctx output; // Non critical access
    init_bytearray_ctx(&output);

    if (_output == NULL) {
        ret_code = mlxkem_get_public_encoded(key_spec, NULL, 0);
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = mlxkem_get_public_encoded(key_spec, output.bytearray, output.size);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI
 * Method:    ni_getPrivateKey
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1getPrivateKey
(JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    int32_t ret_code = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_code)) {
        return ret_code;
    }

    if (_output == NULL) {
        return mlxkem_get_private_encoded(key_spec, NULL, 0);
    }

    // The private half goes through the secret helper: cleansed, and written back only on success.
    java_secret_bytearray_ctx output;
    init_secret_bytearray_ctx(&output);
    if (OPS_FAILED_ACCESS_2 !load_secret_output_ctx(&output, env, _output)) {
        discard_secret_bytearray_ctx(&output);
        return JO_FAILED_ACCESS_OUTPUT;
    }

    ret_code = mlxkem_get_private_encoded(key_spec, output.bytearray, output.size);
    if (SUCCESSFUL(ret_code)) {
        release_secret_bytearray_ctx(&output);
    } else {
        discard_secret_bytearray_ctx(&output);
    }
    return ret_code;
}

/*
 * Shared body for the two decode entry points: the spec, then (private only) the RandSource, then the input,
 * tested before it is loaded. The input goes through the secret helper on both paths; on the private path it is
 * the private half. A null array with off == len == 0 passes the range check, so the explicit null test matters.
 */
static jint mlxkem_decode_bridge(JNIEnv *env, jlong ref, jint key_type, jbyteArray _input,
                                 jint in_off, jint in_len, jobject rnd_src, int is_private) {
    key_spec *key_spec = (void *) ref;

    jint ret_val = key_spec_check(key_spec);
    if (UNSUCCESSFUL(ret_val)) {
        return ret_val;
    }

    java_secret_bytearray_ctx input;
    init_secret_bytearray_ctx(&input);

    if (is_private && rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    if (_input == NULL) {
        ret_val = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_3 !load_secret_input_ctx(&input, env, _input)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (in_off < 0) {
        ret_val = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret_val = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_secret_in_range(&input, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    uint8_t *start = input.bytearray + in_off;
    ret_val = is_private
                  ? mlxkem_decode_private_key(key_spec, key_type, start, (size_t) in_len, rnd_src)
                  : mlxkem_decode_public_key(key_spec, key_type, start, (size_t) in_len);

exit:
    release_secret_bytearray_ctx(&input);
    return ret_val;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI
 * Method:    ni_decode_publicKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1decode_1publicKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(jo);
    return mlxkem_decode_bridge(env, ref, key_type, _input, in_off, in_len, NULL, 0);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI
 * Method:    ni_decode_privateKey
 * Signature: (JI[BIILorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlxkem_MLXKEMServiceJNI_ni_1decode_1privateKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len,
 jobject rnd_src) {
    UNUSED(jo);
    return mlxkem_decode_bridge(env, ref, key_type, _input, in_off, in_len, rnd_src, 1);
}

//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <assert.h>
#include <openssl/asn1.h>

#include "bytearrays.h"
#include "byte_array_critical.h"
#include "org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/key_spec.h"
#include "../util/mlkem.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI
 * Method:    generateKeyPair
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_generateKeyPair__I
(JNIEnv *env, jobject jo, jint type) {
    UNUSED(jo);
    UNUSED(env);

    jint ret_val = JO_FAIL;

    key_spec *key_spec = create_spec();
    ret_val = mlkem_generate_key_pair(key_spec, type, NULL, 0);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(key_spec);
        return ret_val;
    }

    return (jlong) key_spec;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI
 * Method:    generateKeyPair
 * Signature: (I[BI)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_generateKeyPair__I_3BI
(JNIEnv *env, jobject jo, jint type, jbyteArray _seed, jint seed_len) {
    UNUSED(jo);
    UNUSED(env);

    java_bytearray_ctx seed; // Non critical access
    init_bytearray_ctx(&seed);

    int64_t ret_code = JO_FAIL;

    if (_seed == NULL) {
        ret_code = JO_SEED_IS_NULL;
        goto exit;
    }

    if (seed_len < 0) {
        ret_code = JO_SEED_LEN_IS_NEGATIVE;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&seed, env, _seed)) {
        ret_code = JO_FAILED_ACCESS_SEED;
        goto exit;
    }

    if ((size_t)seed_len > seed.size) { // seed_len asserted non-negative by this point
        ret_code = JO_INVALID_SEED_LEN_OUT_OF_RANGE;
        goto exit;
    }


    key_spec *key_spec = create_spec();
    ret_code = mlkem_generate_key_pair(key_spec, type, seed.bytearray, seed_len);

    if (ret_code != JO_SUCCESS) {
        free_key_spec(key_spec);
    } else {
        ret_code = (jlong) key_spec;
    }

exit:
    release_bytearray_ctx(&seed);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI
 * Method:    getPublicKey
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_getPublicKey(
    JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    if (key_spec == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }


    java_bytearray_ctx output; // Non critical access
    init_bytearray_ctx(&output);

    int32_t ret_code = JO_FAIL;

    if (_output == NULL) {
        ret_code = mlkem_get_public_encoded(key_spec,NULL, 0);
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = mlkem_get_public_encoded(key_spec, output.bytearray, output.size);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI
 * Method:    getPrivateKey
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_getPrivateKey(
    JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;

    java_bytearray_ctx output; // Non critical access
    init_bytearray_ctx(&output);

    int32_t ret_code = JO_FAIL;


    if (key_spec == NULL) {
        ret_code = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }


    if (_output == NULL) {
        ret_code = mlkem_get_private_encoded(key_spec,NULL, 0);
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = mlkem_get_private_encoded(key_spec, output.bytearray, output.size);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI
 * Method:    getSeed
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_getSeed
(JNIEnv *env, jobject o, jlong ref, jbyteArray _output) {
    UNUSED(o);
    key_spec *key_spec = (void *) ref;


    java_bytearray_ctx output; // Non critical access
    init_bytearray_ctx(&output);

    int32_t ret_code = JO_FAIL;

    if (key_spec == NULL) {
        ret_code = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (key_spec->key == NULL) {
        ret_code = JO_KEY_SPEC_HAS_NULL_KEY;
        goto exit;
    }

    if (_output == NULL) {
        ret_code = mlkem_get_private_seed(key_spec,NULL, 0);
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    ret_code = mlkem_get_private_seed(key_spec, output.bytearray, output.size);

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI
 * Method:    decode_publicKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI_decode_1publicKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    key_spec *key_spec = (void *) ref;


    jint ret_val = JO_FAIL;
    java_bytearray_ctx input; // Non critical access
    init_bytearray_ctx(&input);

    if (key_spec == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (input.array == NULL) {
        ret_val = JO_INPUT_IS_NULL;;
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

    if (!check_bytearray_in_range(&input, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    // key_spec->type = key_type;

    uint8_t *start = input.bytearray + in_off;
    ret_val = mlkem_decode_public_key(key_spec, key_type, start, in_len);


exit:
    release_bytearray_ctx(&input);
    return ret_val;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI
 * Method:    decode_privateKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLDSAServiceJNI_decode_1privateKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    key_spec *key_spec = (void *) ref;


    jint ret_val = JO_FAIL;
    java_bytearray_ctx input; // Non critical access
    init_bytearray_ctx(&input);

    if (key_spec == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (input.array == NULL) {
        ret_val = JO_INPUT_IS_NULL;;
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

    if (!check_bytearray_in_range(&input, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    // key_spec->type = key_type;

    uint8_t *start = input.bytearray + in_off;
    ret_val = mlkem_decode_private_key(key_spec, key_type, start, in_len);


exit:
    release_bytearray_ctx(&input);
    return ret_val;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI
 * Method:    decode_publicKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_decode_1publicKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    key_spec *key_spec = (void *) ref;


    jint ret_val = JO_FAIL;
    java_bytearray_ctx input; // Non critical access
    init_bytearray_ctx(&input);

    if (key_spec == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (input.array == NULL) {
        ret_val = JO_INPUT_IS_NULL;;
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

    if (!check_bytearray_in_range(&input, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    uint8_t *start = input.bytearray + in_off;
    ret_val = mlkem_decode_public_key(key_spec,key_type, start, in_len);


exit:
    release_bytearray_ctx(&input);
    return ret_val;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI
 * Method:    decode_privateKey
 * Signature: (JI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_mlkem_MLKEMServiceJNI_decode_1privateKey
(JNIEnv *env, jobject jo, jlong ref, jint key_type, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    key_spec *key_spec = (void *) ref;


    jint ret_val = JO_FAIL;
    java_bytearray_ctx input; // Non critical access
    init_bytearray_ctx(&input);

    if (key_spec == NULL) {
        ret_val = JO_KEY_SPEC_IS_NULL;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret_val = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (input.array == NULL) {
        ret_val = JO_INPUT_IS_NULL;;
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

    if (!check_bytearray_in_range(&input, in_off, in_len)) {
        ret_val = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    uint8_t *start = input.bytearray + in_off;
    ret_val = mlkem_decode_private_key(key_spec, key_type, start, in_len);


exit:
    release_bytearray_ctx(&input);
    return ret_val;
}

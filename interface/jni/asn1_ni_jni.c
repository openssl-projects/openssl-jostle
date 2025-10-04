//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <assert.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "bytearrays.h"
#include "org_openssl_jostle_util_asn1_Asn1NiJNI.h"
#include "types.h"
#include "../util/asn1_util.h"
#include "../util/ops.h"

/*
 * Class:     org_openssl_jostle_util_asn1_Asn1NiJNI
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_util_asn1_Asn1NiJNI_dispose
(JNIEnv *env, jobject jo, jlong ref) {
    UNUSED(env);
    UNUSED(jo);

    asn1_ctx *ctx = (asn1_ctx *) ref;
    if (ctx == NULL) {
        return;
    }
    asn1_writer_free(ctx);
}

/*
 * Class:     org_openssl_jostle_util_asn1_Asn1NiJNI
 * Method:    allocate
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_util_asn1_Asn1NiJNI_allocate
(JNIEnv *env, jobject jo) {
    UNUSED(env);
    UNUSED(jo);
    asn1_ctx *ctx = asn1_writer_allocate();
    assert(ctx != NULL);
    return (jlong) ctx;
}

/*
 * Class:     org_openssl_jostle_util_asn1_Asn1NiJNI
 * Method:    encodePublicKey
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_util_asn1_Asn1NiJNI_encodePublicKey
(JNIEnv *env, jobject jo, jlong asn1_ref, jlong key_ref) {
    UNUSED(env);
    UNUSED(jo);

    asn1_ctx *ctx = (asn1_ctx *) asn1_ref;
    assert(ctx != NULL);

    key_spec *key = (key_spec *) key_ref;

    if (key == NULL) {
        return JO_KEY_IS_NULL;
    }

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }


    size_t buf_len = 0;
    if (!asn1_writer_encode_public_key(ctx, key, &buf_len)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_1 buf_len > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (jint) buf_len;
}

/*
 * Class:     org_openssl_jostle_util_asn1_Asn1NiJNI
 * Method:    encodePrivateKey
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_util_asn1_Asn1NiJNI_encodePrivateKey
(JNIEnv *env, jobject jo, jlong asn1_ref, jlong key_ref) {
    UNUSED(env);
    UNUSED(jo);

    asn1_ctx *ctx = (asn1_ctx *) asn1_ref;
    assert(ctx != NULL);

    key_spec *key = (key_spec *) key_ref;

    if (key == NULL) {
        return JO_KEY_IS_NULL;
    }

    if (key->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    size_t buf_len = 0;
    if (!asn1_writer_encode_private_key(ctx, key, &buf_len)) {
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_1 buf_len > INT_MAX) {
        return JO_OUTPUT_SIZE_INT_OVERFLOW;
    }

    return (jint) buf_len;
}

/*
 * Class:     org_openssl_jostle_util_asn1_Asn1NiJNI
 * Method:    getData
 * Signature: (J[B)J
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_util_asn1_Asn1NiJNI_getData
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _output) {
    UNUSED(jo);

    asn1_ctx *ctx = (asn1_ctx *) ref;
    assert(ctx != NULL);
    int32_t ret_code = JO_FAIL;

    java_bytearray_ctx output;
    init_bytearray_ctx(&output);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&output, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    size_t buf_len = 0;

    const int32_t ret = asn1_writer_get_content(ctx, output.bytearray, &buf_len, output.size);

    if (ret != 1) {
        ret_code = ret;
        goto exit;
    }

    if (OPS_INT32_OVERFLOW_1 buf_len > INT_MAX) {
        ret_code = JO_OUTPUT_SIZE_INT_OVERFLOW;
        goto exit;
    }

    ret_code = (int32_t) buf_len;

exit:
    release_bytearray_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_util_asn1_Asn1NiJNI
 * Method:    fromPrivateKeyInfo
 * Signature: ([BII)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_util_asn1_Asn1NiJNI_fromPrivateKeyInfo
(JNIEnv *env, jobject jo, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);
    int32_t ret_code = JO_FAIL;
    key_spec *spec = NULL;


    java_bytearray_ctx input;
    init_bytearray_ctx(&input);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    if (input.bytearray == NULL) {
        ret_code = JO_INPUT_IS_NULL;
        goto exit;
    }


    if (in_off < 0) {
        ret_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_bytearray_in_range(&input, in_off, in_len)) {
        ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    // in_off is asserted non-negative by this point
    uint8_t *data = input.bytearray + in_off;


    spec = asn1_writer_decode_private_key(data, in_len, &ret_code);


exit:
    release_bytearray_ctx(&input);
    if (spec != NULL) {
        return (jlong) spec;
    }
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_util_asn1_Asn1NiJNI
 * Method:    fromPublicKeyInfo
 * Signature: ([BII)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_util_asn1_Asn1NiJNI_fromPublicKeyInfo
(JNIEnv *env, jobject jo, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(env);
    UNUSED(jo);

    int32_t ret_code = JO_FAIL;
    key_spec *spec = NULL;

    java_bytearray_ctx input;
    init_bytearray_ctx(&input);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&input, env, _input)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    if (in_off < 0) {
        ret_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_bytearray_in_range(&input, in_off, in_len)) {
        ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    // in_off is asserted non-negative by this point
    const uint8_t *data = input.bytearray + in_off;


    spec = asn1_writer_decode_public_key(data, in_len, &ret_code);


exit:
    release_bytearray_ctx(&input);
    if (spec != NULL) {
        return (jlong) spec;
    }
    return ret_code;
}

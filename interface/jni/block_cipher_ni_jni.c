//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include <assert.h>
#include <openssl/evp.h>

#include "byte_array_critical.h"
#include "org_openssl_jostle_jcajce_provider_BlockCipherJNI.h"
#include "types.h"
#include "../util/block_cipher_ctx.h"
#include "bytearrays.h"
#include "../util/ops.h"

/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    makeInstance
 * Signature: (III)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_makeInstance
(JNIEnv *env, jobject cl, jint cipherId, jint modeId, jint padding) {
    UNUSED(env);
    UNUSED(cl);

    block_cipher_ctx *ctx = block_cipher_ctx_create(cipherId, modeId, padding);
    return (jlong) ctx;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    init
 * Signature: (JI[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_init
(JNIEnv *env, jobject cl, jlong ref, jint opp_mode, jbyteArray _key, jbyteArray _iv, jint tag_len) {
    UNUSED(cl);

    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);
    jint return_code = JO_FAIL;
    java_bytearray_ctx key;
    java_bytearray_ctx iv;

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&key, env, _key)) {
        return_code = JO_FAILED_ACCESS_KEY;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&iv, env, _iv)) {
        release_bytearray_ctx(&key);
        return_code = JO_FAILED_ACCESS_IV;
        goto exit;
    }

    if (tag_len < 0) {
        return_code = JO_INVALID_TAG_LEN;
        goto exit;
    }

    if (key.bytearray == NULL) {
        return_code = JO_KEY_IS_NULL;
        goto exit;
    }

    return_code = block_cipher_ctx_init(
        ctx,
        opp_mode,
        key.bytearray,
        key.size,
        iv.bytearray,
        iv.size, tag_len);

exit:
    release_bytearray_ctx(&key);
    release_bytearray_ctx(&iv);
    return return_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    getBlockSize
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_getBlockSize
(JNIEnv *env, jobject cl, jlong ref) {
    UNUSED(env);
    UNUSED(cl);

    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);
    return block_cipher_ctx_get_block_size(ctx);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    updateAAD
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_updateAAD
(JNIEnv *env, jobject cl, jlong ref, jbyteArray _input,
 jint in_off,
 jint in_len) {
    UNUSED(env);
    UNUSED(cl);

    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);
    jint return_code = JO_FAIL;

    critical_bytearray_ctx input;

    init_critical_ctx(&input, env, _input);


    if (input.array == NULL) {
        return_code = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (in_off < 0) {
        return_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        return_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_critical_in_range(&input, in_off, in_len)) {
        return_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    /* Request access to critical regions from JVM  */

    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&input)) {
        return_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    /* in_off and out_off asserted as non-negative by this point */
    /* in_off and out_off asserted as in range by this point */

    uint8_t *input_data = input.critical + (size_t) in_off;

    return_code = block_cipher_ctx_updateAAD(ctx, input_data, in_len);

exit:
    release_critical_ctx(&input);

    return return_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    update
 * Signature: (J[BI[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_update
(
    JNIEnv *env,
    jobject cl,
    jlong ref,
    jbyteArray _output,
    jint out_off,
    jbyteArray _input,
    jint in_off,
    jint in_len) {
    UNUSED(cl);

    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);
    jint return_code = JO_FAIL;
    size_t out_len;

    critical_bytearray_ctx input;
    critical_bytearray_ctx output;

    init_critical_ctx(&input, env, _input);
    init_critical_ctx(&output, env, _output);

    if (input.array == NULL) {
        return_code = JO_INPUT_IS_NULL;
        goto exit;
    }

    if (output.array == NULL) {
        return_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_off < 0) {
        return_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_off < 0) {
        return_code = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        return_code = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_critical_in_range(&input, in_off, in_len)) {
        return_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }


    /* out_off asserted as non-negative by this point */
    out_len = output.size - (size_t) out_off;

    if (!check_critical_in_range(&output, out_off, out_len)) {
        return_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    /* Request access to critical regions from JVM  */

    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&input)) {
        return_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_2 !load_critical_ctx(&output)) {
        return_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }


    /* in_off and out_off asserted as non-negative by this point */
    /* in_off and out_off asserted as in range by this point */

    uint8_t *input_data = input.critical + (size_t) in_off;
    uint8_t *output_data = output.critical + (size_t) out_off;

    return_code = block_cipher_ctx_update(ctx, input_data, in_len, output_data, out_len);

exit:
    release_critical_ctx(&output);
    release_critical_ctx(&input);

    return return_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    doFinal
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_doFinal
(JNIEnv *env, jobject cl, jlong ref, jbyteArray _output, jint out_off) {
    UNUSED(cl);
    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);

    jint return_code = JO_FAIL;
    size_t out_len;
    critical_bytearray_ctx output;
    init_critical_ctx(&output, env, _output);

    if (output.array == NULL) {
        return_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_off < 0) {
        return_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    /* out_off asserted as non-negative by this point */
    out_len = output.size - (size_t) out_off;

    if (OPS_FAILED_ACCESS_1 !check_critical_in_range(&output, out_off, out_len)) {
        return_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_2 !load_critical_ctx(&output)) {
        return_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    uint8_t *output_data = output.critical + (size_t) out_off;

    return_code = block_cipher_ctx_final(ctx, output_data, out_len);

exit:
    release_critical_ctx(&output);
    return return_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    getFinalSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_getFinalSize
(JNIEnv *env, jobject obj, jlong ref, jint len) {
    UNUSED(obj);
    UNUSED(env);
    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);

    int32_t return_code = JO_FAIL;

    if (len < 0) {
        return_code = JO_FINAL_SIZE_LEN_IS_NEGATIVE;
        goto exit;
    }

    return_code = block_cipher_get_final_size(ctx, (size_t) len);

exit:
    return return_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    getUpdateSize
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_getUpdateSize
(JNIEnv *env, jobject obj, jlong ref, jint len) {
    UNUSED(env);
    UNUSED(obj);

    block_cipher_ctx *ctx = (block_cipher_ctx *) ((void *) ref);
    assert(ctx);

    int32_t return_code = JO_FAIL;

    if (len < 0) {
        return_code = JO_FINAL_SIZE_LEN_IS_NEGATIVE;
        goto exit;
    }

    return_code = block_cipher_get_update_size(ctx, (size_t) len);

exit:
    return return_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_BlockCipherJNI
 * Method:    dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_BlockCipherJNI_dispose
(JNIEnv *env, jobject cl, jlong ref) {
    UNUSED(cl);
    UNUSED(env);
    block_cipher_ctx *ctx = (block_cipher_ctx *) ref;
    block_cipher_ctx_destroy(ctx);
}

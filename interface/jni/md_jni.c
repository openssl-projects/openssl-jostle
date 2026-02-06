//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <assert.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "byte_array_critical.h"
#include "org_openssl_jostle_jcajce_provider_md_MDServiceJNI.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/md.h"
#include "../util/ops.h"

/*
 * Class:     org_openssl_jostle_jcajce_provider_md_MDServiceJNI
 * Method:    ni_allocateDigest
 * Signature: (Ljava/lang/String;[I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1allocateDigest
(JNIEnv *env, jobject jo, jstring _digest, jint xof_len, jintArray _err) {
    UNUSED(jo);

    int32_t *err = NULL;
    md_ctx *md_ctx = NULL;
    const char *name = NULL;

    //
    // err needs to be defined and accessible
    //
    assert(_err != NULL);
    err = (*env)->GetIntArrayElements(env, _err, NULL);
    assert(err != NULL);

    if (_digest == NULL) {
        err[0] = JO_NAME_IS_NULL;
        goto exit;
    }

    name = (*env)->GetStringUTFChars(env, _digest, NULL);
    if (name == NULL) {
        err[0] = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    md_ctx = md_ctx_create(name, xof_len, err);

exit:
    if (name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _digest, name);
    }

    (*env)->ReleaseIntArrayElements(env, _err, err, 0);

    return (jlong) md_ctx;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_md_MDServiceJNI
 * Method:    ni_updateByte
 * Signature: (JB)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1updateByte
(JNIEnv *env, jobject jo, jlong ref, jbyte data) {
    UNUSED(env);
    UNUSED(jo);

    int32_t ret_code = JO_FAIL;

    md_ctx *ctx = (md_ctx *) ref;
    assert(ctx != NULL);

    ret_code = md_ctx_update(ctx, (uint8_t *) &data, 1);

    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_md_MDServiceJNI
 * Method:    ni_updateBytes
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1updateBytes
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _input, jint in_off, jint in_len) {
    UNUSED(jo);

    md_ctx *ctx = (md_ctx *) ref;
    assert(ctx != NULL);

    int32_t ret_code = JO_FAIL;

    critical_bytearray_ctx input;
    init_critical_ctx(&input, env, _input);

    if (input.array == NULL) {
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


    if (!check_critical_in_range(&input, in_off, in_len)) {
        ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&input)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }

    uint8_t *in = input.critical + in_off;
    md_ctx_update(ctx, in, in_len);

exit:
    release_critical_ctx(&input);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_md_MDServiceJNI
 * Method:    ni_dispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1dispose
(JNIEnv *env, jobject o, jlong ref) {
    UNUSED(*env);
    UNUSED(o);

    md_ctx *ctx = (md_ctx *) ref;
    md_ctx_destroy(ctx);
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_md_MDServiceJNI
 * Method:    ni_getDigestOutputLen
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1getDigestOutputLen
(JNIEnv *env, jobject jo, jlong ref) {
    UNUSED(env);
    UNUSED(jo);

    md_ctx *ctx = (md_ctx *) ref;
    assert(ctx != NULL);

    if (ctx->digest_byte_length == 0) {
        return JO_FAIL;
    }

    if (ctx->digest_byte_length > INT_MAX) {
        return JO_MD_DIGEST_LEN_INT_OVERFLOW;
    }

    return (jint) ctx->digest_byte_length;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_md_MDServiceJNI
 * Method:    ni_digest
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1digest
(JNIEnv *env, jobject jo, jlong ref, jbyteArray _output, jint out_off, jint out_len) {
    UNUSED(env);
    UNUSED(jo);

    md_ctx *ctx = (md_ctx *) ref;
    assert(ctx != NULL);

    if (_output == NULL) {
        /* Caller wants length */
        return (jint) ctx->digest_byte_length;
    }

    int32_t ret_code = JO_FAIL;

    critical_bytearray_ctx output;
    init_critical_ctx(&output, env, _output);


    if (out_off < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    /* out_off asserted as non-negative by this point */

    if (!check_critical_in_range(&output, out_off, out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }


    if (OPS_FAILED_ACCESS_1 !load_critical_ctx(&output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }

    uint8_t *output_data = output.critical + (size_t) out_off;


    uint32_t s = 0;

    if (!EVP_DigestFinal_ex(ctx->mdctx, output_data, &s)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (s > INT_MAX) {
        ret_code = JO_MD_DIGEST_LEN_INT_OVERFLOW;
    }

    ret_code = (jint) s;

exit:
    release_critical_ctx(&output);
    return ret_code;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_md_MDServiceJNI
 * Method:    ni_reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_md_MDServiceJNI_ni_1reset
(JNIEnv *env, jobject jo, jlong ref) {
    UNUSED(env);
    UNUSED(jo);

    md_ctx *ctx = (md_ctx *) ref;
    assert(ctx != NULL);

    EVP_MD_CTX_reset(ctx->mdctx);
}

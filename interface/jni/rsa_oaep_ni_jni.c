//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#include <string.h>

#include "bytearrays.h"
#include "org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/rsa_oaep.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI
 * Method:    ni_allocateCipher
 * Signature: ([I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI_ni_1allocateCipher
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(jo);
    jo_assert(err != NULL);

    int rc = 0;
    void *ref = rsa_oaep_ctx_create(&rc);

    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);
    return (jlong) ref;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI
 * Method:    ni_disposeCipher
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI_ni_1disposeCipher
(JNIEnv *env, jobject o, jlong ref) {
    UNUSED(env);
    UNUSED(o);

    rsa_oaep_ctx_destroy((rsa_oaep_ctx *) ref);
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI
 * Method:    ni_init
 * Signature: (JJILjava/lang/String;Ljava/lang/String;[BLorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI_ni_1init
(JNIEnv *env, jobject jo, jlong rsa_ref, jlong key_ref,
 jint op_mode, jstring _oaep_md, jstring _mgf1_md, jbyteArray _label,
 jobject rnd_src) {
    UNUSED(jo);

    rsa_oaep_ctx *ctx = (rsa_oaep_ctx *) rsa_ref;
    jo_assert(ctx != NULL);

    key_spec *key = (key_spec *) key_ref;
    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }
    if (_oaep_md == NULL) {
        return JO_NAME_IS_NULL;
    }

    const char *oaep_md = NULL;
    const char *mgf1_md = NULL;
    java_bytearray_ctx label;
    init_bytearray_ctx(&label);
    int32_t ret_code = JO_FAIL;

    oaep_md = (*env)->GetStringUTFChars(env, _oaep_md, NULL);
    if (oaep_md == NULL) {
        ret_code = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }
    if (_mgf1_md != NULL) {
        mgf1_md = (*env)->GetStringUTFChars(env, _mgf1_md, NULL);
        if (mgf1_md == NULL) {
            ret_code = JO_UNABLE_TO_ACCESS_NAME;
            goto exit;
        }
    }

    const uint8_t *label_bytes = NULL;
    size_t label_len = 0;
    if (_label != NULL) {
        if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&label, env, _label)) {
            ret_code = JO_FAILED_ACCESS_INPUT;
            goto exit;
        }
        label_bytes = label.bytearray;
        label_len = label.size;
    }

    ret_code = rsa_oaep_init(ctx, key, op_mode,
                             oaep_md, mgf1_md,
                             label_bytes, label_len,
                             rnd_src);

exit:
    if (oaep_md != NULL) {
        (*env)->ReleaseStringUTFChars(env, _oaep_md, oaep_md);
    }
    if (mgf1_md != NULL) {
        (*env)->ReleaseStringUTFChars(env, _mgf1_md, mgf1_md);
    }
    release_bytearray_ctx(&label);
    return ret_code;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI
 * Method:    ni_doFinal
 * Signature: (J[BII[BILorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAOAEPCipherJNI_ni_1doFinal
(JNIEnv *env, jobject jo, jlong ref,
 jbyteArray _input, jint in_off, jint in_len,
 jbyteArray _output, jint out_off,
 jobject rnd_src) {
    UNUSED(jo);

    rsa_oaep_ctx *ctx = (rsa_oaep_ctx *) ref;
    jo_assert(ctx != NULL);

    if (_input == NULL) {
        return JO_INPUT_IS_NULL;
    }
    if (in_off < 0) {
        return JO_INPUT_OFFSET_IS_NEGATIVE;
    }
    if (in_len < 0) {
        return JO_INPUT_LEN_IS_NEGATIVE;
    }

    int32_t ret_code = JO_FAIL;
    java_bytearray_ctx in_ctx;
    java_bytearray_ctx out_ctx;
    init_bytearray_ctx(&in_ctx);
    init_bytearray_ctx(&out_ctx);

    if (OPS_FAILED_ACCESS_1 !load_bytearray_ctx(&in_ctx, env, _input)) {
        ret_code = JO_FAILED_ACCESS_INPUT;
        goto exit;
    }
    if (!check_bytearray_in_range(&in_ctx, in_off, in_len)) {
        ret_code = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (_output == NULL) {
        // Caller wants required length only.
        ret_code = rsa_oaep_dofinal(ctx,
                                    in_ctx.bytearray + in_off, (size_t) in_len,
                                    NULL, 0,
                                    rnd_src);
        goto exit;
    }

    if (out_off < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }
    if (OPS_FAILED_ACCESS_2 !load_bytearray_ctx(&out_ctx, env, _output)) {
        ret_code = JO_FAILED_ACCESS_OUTPUT;
        goto exit;
    }
    if ((size_t) out_off > out_ctx.size) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    ret_code = rsa_oaep_dofinal(ctx,
                                in_ctx.bytearray + in_off, (size_t) in_len,
                                out_ctx.bytearray + (size_t) out_off,
                                out_ctx.size - (size_t) out_off,
                                rnd_src);

exit:
    release_bytearray_ctx(&in_ctx);
    release_bytearray_ctx(&out_ctx);
    return ret_code;
}

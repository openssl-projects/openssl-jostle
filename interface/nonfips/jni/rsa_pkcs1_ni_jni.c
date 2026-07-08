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
#include "org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/rsa_pkcs1.h"
#include "../util/ops.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI
 * Method:    ni_allocateCipher
 * Signature: ([I)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI_ni_1allocateCipher
(JNIEnv *env, jobject jo, jintArray err) {
    UNUSED(jo);
    jo_assert(err != NULL);

    int rc = 0;
    void *ref = rsa_pkcs1_ctx_create(&rc);

    (*env)->SetIntArrayRegion(env, err, 0, 1, &rc);
    return (jlong) ref;
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI
 * Method:    ni_disposeCipher
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI_ni_1disposeCipher
(JNIEnv *env, jobject o, jlong ref) {
    UNUSED(env);
    UNUSED(o);

    rsa_pkcs1_ctx_destroy((rsa_pkcs1_ctx *) ref);
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI
 * Method:    ni_init
 * Signature: (JJILorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI_ni_1init
(JNIEnv *env, jobject jo, jlong rsa_ref, jlong key_ref,
 jint op_mode, jobject rnd_src) {
    UNUSED(env);
    UNUSED(jo);

    rsa_pkcs1_ctx *ctx = (rsa_pkcs1_ctx *) rsa_ref;
    jo_assert(ctx != NULL);

    key_spec *key = (key_spec *) key_ref;
    if (key == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    return rsa_pkcs1_init(ctx, key, op_mode, rnd_src);
}


/*
 * Class:     org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI
 * Method:    ni_doFinal
 * Signature: (J[BII[BILorg/openssl/jostle/rand/RandSource;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_rsa_RSAPKCS1CipherJNI_ni_1doFinal
(JNIEnv *env, jobject jo, jlong ref,
 jbyteArray _input, jint in_off, jint in_len,
 jbyteArray _output, jint out_off,
 jobject rnd_src) {
    UNUSED(jo);

    rsa_pkcs1_ctx *ctx = (rsa_pkcs1_ctx *) ref;
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
        ret_code = rsa_pkcs1_dofinal(ctx,
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

    ret_code = rsa_pkcs1_dofinal(ctx,
                                 in_ctx.bytearray + in_off, (size_t) in_len,
                                 out_ctx.bytearray + (size_t) out_off,
                                 out_ctx.size - (size_t) out_off,
                                 rnd_src);

exit:
    release_bytearray_ctx(&in_ctx);
    release_bytearray_ctx(&out_ctx);
    return ret_code;
}

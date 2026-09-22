//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "../util/ops.h"
#include <jni.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bytearrays.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/rand.h"
#include "../util/rand/jostle_lib_ctx.h"


#ifdef JOSTLE_OPS

#include "org_openssl_jostle_util_ops_OperationsTestJNI.h"

/*
* Class:     Java_org_openssl_jostle_util_ops_OperationsTestJNI_setOpsTestFlag
 * Method:    setOpsTestFlag
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_org_openssl_jostle_util_ops_OperationsTestJNI_setOpsTestFlag
(JNIEnv *env, jobject jo, jint index, jint value) {
    UNUSED(env);
    UNUSED(jo);
    set_ops_test(index, value);
}

/*
 * Class:     org_openssl_jostle_util_ops_OperationsTestJNI
 * Method:    op_getEntropy
 * Signature: (Lorg/openssl/jostle/rand/DefaultRandSource;[BIIZ)I
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_util_ops_OperationsTestJNI_op_1createTestDrbg
(JNIEnv *env, jobject o, jstring _mechanism, jstring _variant, jboolean use_df,
 jint strength, jboolean pred, jbyteArray _personalization, jbyteArray _entropy,
 jbyteArray _nonce, jintArray _err) {
    UNUSED(o);

    //
    // Operations testing only, so input verification is forgone as it is on the
    // rest of this surface. The handle returned is an ordinary rand context and
    // is driven and disposed of through RandServiceNI.
    //

    jo_assert(_err != NULL);
    jo_assert((*env)->GetArrayLength(env, _err) >= 1);

    java_bytearray_ctx personalization;
    java_bytearray_ctx entropy;
    java_bytearray_ctx nonce;
    init_bytearray_ctx(&personalization);
    init_bytearray_ctx(&entropy);
    init_bytearray_ctx(&nonce);

    jo_assert(load_bytearray_ctx(&personalization, env, _personalization) != 0);
    jo_assert(load_bytearray_ctx(&entropy, env, _entropy) != 0);
    jo_assert(load_bytearray_ctx(&nonce, env, _nonce) != 0);

    const char *mechanism = (*env)->GetStringUTFChars(env, _mechanism, NULL);
    const char *variant = (*env)->GetStringUTFChars(env, _variant, NULL);
    jo_assert(mechanism != NULL);
    jo_assert(variant != NULL);

    int32_t err = 0;
    JO_RAND_CTX *ctx = rand_ctx_create_test(mechanism, variant, use_df ? 1 : 0, strength,
                                            pred ? 1 : 0,
                                            personalization.bytearray, personalization.size,
                                            entropy.bytearray, entropy.size,
                                            nonce.bytearray, nonce.size, &err);

    (*env)->ReleaseStringUTFChars(env, _mechanism, mechanism);
    (*env)->ReleaseStringUTFChars(env, _variant, variant);
    release_bytearray_ctx(&personalization);
    release_bytearray_ctx(&entropy);
    release_bytearray_ctx(&nonce);

    (*env)->SetIntArrayRegion(env, _err, 0, 1, &err);
    return (jlong) (size_t) ctx;
}

JNIEXPORT jint JNICALL Java_org_openssl_jostle_util_ops_OperationsTestJNI_op_1getEntropy
(JNIEnv *env, jobject o, jbyteArray _out, jint len, jint strength, jboolean pred, jobject rnd_src) {
    UNUSED(o);

    //
    // This method is for testing only and forgoes the usual verification of input
    // It is part of ops testing and users should not be using libs with ops testing compiled in
    // for any other purpose than testing.
    //

    UNUSED(pred); // TODO work out how to test this

    java_bytearray_ctx data;
    init_bytearray_ctx(&data);


    jo_assert(load_bytearray_ctx(&data,env,_out) != 0);

    int rc = OPS_GetRandomBytes(data.bytearray, len, strength, pred, rnd_src);

    release_bytearray_ctx(&data);

    return rc;
}


#endif

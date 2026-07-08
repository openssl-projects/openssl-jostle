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

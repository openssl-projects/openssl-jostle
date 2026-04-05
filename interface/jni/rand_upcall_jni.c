//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//

//
// Created by MEGAN WOODS on 28/3/2026.
//

#include "rand_upcall_jni.h"

#include <jni.h>

#include <string.h>
#include <openssl/err.h>

#include "bytearrays.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/bc_err_codes.h"
#include "../util/ops.h"
#include "../util/rand/jostle_lib_ctx.h"

void rand_up_call_init_jni(JNIEnv *env) {
    int ret = (*env)->GetJavaVM(env, &java_vm);
    jo_assert(ret >= 0);

    //
    // Targeting the interface
    //
    jclass clazz = (*env)->FindClass(env, "org/openssl/jostle/rand/RandSource");
    jo_assert(clazz != NULL);

    target_class = (*env)->NewGlobalRef(env, clazz);
    jo_assert(target_class != NULL);

    target_method = (*env)->GetMethodID(env, target_class, "getRandomBytes", "([BIIZ)I");
    jo_assert(target_method != NULL);
}

int rand_up_call_next_bytes(void *rnd_src, unsigned char *_out, size_t out_len,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *adin, size_t adin_len) {
    //
    // Note: "rnd_src" is set from a thread local accessed from within an implementation of
    // OSSL_FUNC_RAND_GENERATE in jostle_lib_ctx.c
    //

    UNUSED(adin);
    UNUSED(adin_len);
    int rc = JO_FAIL;
    JNIEnv *env = NULL;

    if (OPS_RAND_UP_CALL_NULL rnd_src == NULL) {
        rc = JO_RAND_NO_RAND_UP_CALL;
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "handler fail, rand up call is null: %d", rc);
        return rc;
    }

    if (OPS_INT32_OVERFLOW_1 out_len > INT_MAX) {
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "out_len > INT_MAX: %d", JO_OPENSSL_ERROR);
        return JO_OPENSSL_ERROR;
    }

    if (OPS_INT32_OVERFLOW_2 strength > INT_MAX) {
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "strength > INT_MAX: %d", JO_OPENSSL_ERROR);
        return JO_OPENSSL_ERROR;
    }

    //
    // OpenSSL might call this from non JVM thread.
    //
    rc = (*java_vm)->AttachCurrentThread(java_vm, (void *) &env, NULL);
    if (OPS_THREAD_ATTACH_1 rc < JNI_OK) {
        rc = JO_RAND_ERROR;
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "handler fail, attach thread: %d", rc);
        return rc;
    }


    jbyteArray bytes = (*env)->NewByteArray(env, (jsize) out_len);
    if (OPS_FAILED_CREATE_1 bytes == NULL) {
        rc = JO_RAND_ERROR;
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "handler fail, create bytearray: %d", rc);
        goto exit;
    }


    const int pr = prediction_resistance == 0 ? JNI_FALSE : JNI_TRUE;


    //
    // Request random data.
    //

    rc = (*env)->CallIntMethod(
        env,
        (jobject) rnd_src,
        target_method,
        bytes,
        (jint) out_len,
        strength,
        pr);


    if (OPS_SHORT_SIZE_1 rc >= 0 && rc < (int) out_len) {
        rc = JO_RAND_UP_SHORT_RESULT;
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "handler fail, short output: %d", rc);
        goto exit;
    }

    uint8_t *output = (uint8_t *) (*env)->GetByteArrayElements(env, bytes, NULL);
    if (OPS_FAILED_ACCESS_2 output == NULL) {
        rc = JO_RAND_FAIL_ACCESS_BUFFER;
        ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "handler fail, access bytearray: %d", rc);
        goto exit;
    }

    if (rc >= 0) {
        memcpy(_out, output, rc);
    }

    // returns void, nothing to check
    (*env)->ReleaseByteArrayElements(env, bytes, (jbyte *) output, 0);

exit:

    if (env != NULL) {
        // deliberately ignoring the error because it can't detach
        (*java_vm)->DetachCurrentThread(java_vm);
    }
    return rc;
}

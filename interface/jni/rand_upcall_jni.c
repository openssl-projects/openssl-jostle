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
#include "bytearrays.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/bc_err_codes.h"
#include "../util/rand/jostle_lib_ctx.h"

void rand_up_call_init_jni(JNIEnv *env) {
    int ret = (*env)->GetJavaVM(env, &java_vm);
    jo_assert(ret >= 0);

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
    UNUSED(adin);
    UNUSED(adin_len);
    int rc = JO_FAIL;

    JNIEnv *env = NULL;

    //
    // Some mysterious force in OpenSSL might call this from non JVM thread.
    //
    rc = (*java_vm)->AttachCurrentThread(java_vm, (void *) &env, NULL);
    if (rc < 0) {
        rc = JO_FAIL;
        goto exit;
    }


    jbyteArray bytes = (*env)->NewByteArray(env, (jsize) out_len);
    if (bytes == NULL) {
        rc = JO_RAND_ERROR;
        goto exit;
    }


    const int pr = prediction_resistance == 0 ? JNI_FALSE : JNI_TRUE;

    jo_assert(rnd_src != NULL);
    jo_assert(target_method != NULL);

    rc = (*env)->CallIntMethod(
        env,
        (jobject) rnd_src,
        target_method,
        bytes,
        (jint) out_len,
        strength,
        pr,
        0);

    if (rc >= 0 && rc < (int)out_len) {
        rc = JO_RAND_UP_SHORT_RESULT;
        goto exit;
    }

    uint8_t *output = (uint8_t *) (*env)->GetByteArrayElements(env, bytes, NULL);
    if ( output == NULL ) {
        rc = JO_RAND_ERROR;
        goto exit;
    }

    if (rc >= 0) {
        memcpy(_out, output, rc);
    }

    (*env)->ReleaseByteArrayElements(env, bytes, (jbyte *) output, 0);

exit:

    if (env != NULL) {
        // Will not detach if there are java methods on the call stack.
        // TODO determine attachment
        (*java_vm)->DetachCurrentThread(java_vm);
    }
    return rc;
}

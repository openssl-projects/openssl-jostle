//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "../util/ops.h"
#include <jni.h>
#include "types.h"


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

#endif

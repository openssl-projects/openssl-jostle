//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "org_openssl_jostle_jcajce_provider_xec_XECServiceJNI.h"
#include "types.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/xec.h"
#include "../util/ops.h"

/*
 * JNI bridge for X25519 / X448 key generation. Mirrors the EC keygen
 * bridge (ec_ni_jni.c): null-check the user-supplied name and RandSource,
 * fetch the UTF-8 name, delegate to xec_generate_key, and release the
 * string on every exit path. The kex (derive) path is shared with EC and
 * lives in ec_ni_jni.c — XEC adds only keygen.
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_xec_XECServiceJNI_ni_1generateKeyPair
(JNIEnv *env, jobject jo, jstring _name, jintArray err_out, jobject rnd_src) {
    UNUSED(jo);
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *spec = NULL;
    const char *name = NULL;

    if (_name == NULL) {
        ret_val = JO_NAME_IS_NULL;
        goto exit;
    }
    if (rnd_src == NULL) {
        ret_val = JO_RAND_NO_RAND_UP_CALL;
        goto exit;
    }

    name = (*env)->GetStringUTFChars(env, _name, NULL);
    if (OPS_FAILED_ACCESS_1 name == NULL) {
        ret_val = JO_UNABLE_TO_ACCESS_NAME;
        goto exit;
    }

    spec = create_spec();
    ret_val = xec_generate_key(spec, name, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(spec);
        spec = NULL;
    }

exit:
    if (name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _name, name);
    }
    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) spec;
}

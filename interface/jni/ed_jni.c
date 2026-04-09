//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#include "org_openssl_jostle_jcajce_provider_ed_EDServiceJNI.h"
#include "../util/jo_assert.h"
#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/edec.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_ed_EDServiceJNI
 * Method:    ni_generateKeyPair
 * Signature: (I[ILorg/openssl/jostle/rand/RandSource;)J
 */
JNIEXPORT jlong JNICALL Java_org_openssl_jostle_jcajce_provider_ed_EDServiceJNI_ni_1generateKeyPair
(JNIEnv *env, jobject jo, jint type, jintArray err_out, jobject rnd_src) {
    jo_assert(err_out != NULL);

    jint ret_val = JO_FAIL;
    key_spec *key_spec = create_spec();

    ret_val = edec_generate_key(key_spec, type, rnd_src);

    if (ret_val != JO_SUCCESS) {
        free_key_spec(key_spec);
        key_spec = NULL;
    }

    (*env)->SetIntArrayRegion(env, err_out, 0, 1, &ret_val);
    return (jlong) key_spec;
}

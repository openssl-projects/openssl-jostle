//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <jni.h>
#include <openssl/bio.h>

#include "org_openssl_jostle_jcajce_provider_OpenSSLJNI.h"
#include <openssl/provider.h>
#include <openssl/err.h>
#include <string.h>

#include "rand_upcall_jni.h"
#include "types.h"
#include "../util/bc_err_codes.h"
#include "../util/jo_assert.h"
#include "../util/rand/jostle_lib_ctx.h"


/*
 * Class:     org_openssl_jostle_jcajce_provider_OpenSSLJNI
 * Method:    setOSSLProviderModule
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_openssl_jostle_jcajce_provider_OpenSSLJNI_setOSSLProviderModule(
    JNIEnv *env, jclass cl, jstring _prov_name) {
    UNUSED(cl);

    const char *prov_name = NULL;
    int result = JO_FAIL;


    if (_prov_name == NULL) {
        result = JO_PROV_NAME_NULL;
        goto exit;
    }

    jsize len = (*env)->GetStringLength(env, _prov_name);

    if (len == 0) {
        result = JO_PROV_NAME_EMPTY;
        goto exit;
    }


    // jostle_ctx_init_new owns rnd: allocates on entry, frees on failure.
    jostle_lib_ctx *rnd = NULL;

    prov_name = (*env)->GetStringUTFChars(env, _prov_name, NULL);

    result = jostle_ctx_init_new(&rnd, prov_name);
    if (UNSUCCESSFUL(result)) {
        // rnd is NULL: init_new freed it.
        goto exit;
    }

    result = set_global_jostle_lib_ctx(rnd);

    if (UNSUCCESSFUL(result)) {
        // rnd owns libctx + providers + rand_ctx; plain OPENSSL_free leaks them.
        jostle_ctx_destroy(rnd);
        goto exit;
    }

    rand_up_call_init_jni(env);


exit:
    if (prov_name != NULL) {
        (*env)->ReleaseStringUTFChars(env, _prov_name, prov_name);
    }
    return result;
}

/*
 * Class:     org_openssl_jostle_jcajce_provider_OpenSSLJNI
 * Method:    getOSSLErrors
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_openssl_jostle_jcajce_provider_OpenSSLJNI_getOSSLErrors
(JNIEnv *env, jclass cl) {
    UNUSED(cl);

    BIO *bio = BIO_new(BIO_s_mem());

    if (bio == NULL) {
        return (*env)->NewStringUTF(env, "bio was null");
    }

    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *) calloc(1, 1 + len); // Overallocating by 1 to add trailing zero
    jo_assert(ret != NULL);
    memcpy(ret, buf, len);
    BIO_free(bio);

    /* Create java string */
    jstring str = (*env)->NewStringUTF(env, ret);
    free(ret);
    return str;
}
